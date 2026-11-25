import datetime as dt, pytest
from app.services import compute_score, level, normalize
def ev(ts, **k): return {"timestamp": ts, "event_type": "login", "source": "authentication", **k}
T0 = dt.datetime(2026, 1, 1, 12)
def burst(user, ip="203.0.113.9", n=6): return [ev((T0 + dt.timedelta(seconds=20 * i)).isoformat(), user=user, ip=ip, status="failure") for i in range(n)]

# --- risk scoring ---
def test_levels(): assert [level(x) for x in (0, 29, 30, 59, 60, 79, 80, 100)] == ["low", "low", "medium", "medium", "high", "high", "critical", "critical"]
def test_score_bounds_and_explained():
    s, f, x = compute_score("critical", 1, 10, 10, "admin", True); assert 0 <= s <= 100 and "Threat severity" in x
def test_score_monotonic():
    lo = compute_score("low", .5, 0, 0, "user", False)[0]; hi = compute_score("high", .9, 2, 10, "admin", True)[0]; assert hi > lo
def test_confidence_lowers_score(): assert compute_score("high", .2, 0, 0, "user", False)[0] < compute_score("high", 1, 0, 0, "user", False)[0]

# --- normalization / validation ---
def test_normalize_ok():
    n = normalize({"time": "2026-01-01T12:00:00Z", "type": "login", "src_ip": "10.0.0.1", "result": "403"}, "api_gateway"); assert n["status"] == "denied" and n["source"] == "api_gateway"
@pytest.mark.parametrize("bad", [{"event_type": "x"}, {"timestamp": "2026-01-01T00:00:00Z"}, {"timestamp": "nope", "event_type": "x"}, {"timestamp": "2026-01-01T00:00:00Z", "event_type": "x", "ip": "999.1.1.1"}, "str"])
def test_normalize_rejects(bad):
    with pytest.raises((ValueError, TypeError)): normalize(bad)

# --- detection + correlation + API workflow ---
def test_auth_required(client): assert client.get("/api/events").status_code == 401
def test_bad_login(client): assert client.post("/api/auth/login", json={"email": "admin@sentinelx.local", "password": "wrong"}).status_code == 401
def test_register_and_refresh(client):
    r = client.post("/api/auth/register", json={"email": "a@b.co", "full_name": "A", "password": "longenoughpw1"}); assert r.status_code == 201
    l = client.post("/api/auth/login", json={"email": "a@b.co", "password": "longenoughpw1"}).json()
    r2 = client.post("/api/auth/refresh", json={"refresh_token": l["refresh_token"]}); assert r2.status_code == 200
    assert client.post("/api/auth/refresh", json={"refresh_token": l["refresh_token"]}).status_code == 401  # rotated
def test_rbac(client):
    l = client.post("/api/auth/login", json={"email": "a@b.co", "password": "longenoughpw1"}).json()
    assert client.get("/api/users", headers={"Authorization": "Bearer " + l["access_token"]}).status_code == 403
def test_ingest_validation_and_dupes(client, admin):
    e = ev(T0.isoformat(), user="v1", ip="10.1.1.1", status="success")
    r = client.post("/api/events/ingest", json={"events": [e, e, {"bad": 1}]}, headers=admin).json()
    assert r["accepted"] == 1 and r["duplicates"] == 1 and len(r["invalid"]) == 1
def test_upload_rules(client, admin):
    assert client.post("/api/events/upload", files={"file": ("x.exe", b"x")}, headers=admin).status_code == 415
    assert client.post("/api/events/upload", files={"file": ("x.csv", b"a" * (2 * 1024 * 1024 + 5))}, headers=admin).status_code == 413
def test_bruteforce_chain_incident_workflow(client, admin):
    base = [ev((T0 - dt.timedelta(days=1, hours=i)).isoformat(), user="victim", ip="10.2.2.2", status="success") for i in range(4)]
    chain = burst("victim") + [ev((T0 + dt.timedelta(minutes=5)).isoformat(), user="victim", ip="203.0.113.9", status="success"),
        {"timestamp": (T0 + dt.timedelta(minutes=8)).isoformat(), "event_type": "resource_access", "user": "victim", "ip": "203.0.113.9", "action": "export", "resource": "/payroll/export", "status": "success", "source": "application"}]
    assert client.post("/api/events/ingest", json={"events": base + chain}, headers=admin).json()["accepted"] == len(base + chain)
    th = client.get("/api/threats?size=100", headers=admin).json()["items"]; cats = {t["category"] for t in th if t["user"] == "victim"}
    assert {"Multiple failed logins", "Login from unusual IP", "Unusual access to sensitive resource"} <= cats
    inc = [i for i in client.get("/api/incidents?size=100", headers=admin).json()["items"] if "victim" in i["title"]][0]
    assert inc["risk_level"] in ("high", "critical")
    iid = inc["id"]; assert client.patch(f"/api/incidents/{iid}", json={"status": "investigating"}, headers=admin).status_code == 200
    assert client.post(f"/api/incidents/{iid}/notes", json={"body": "Reset password", "kind": "remediation"}, headers=admin).status_code == 201
    assert client.patch(f"/api/incidents/{iid}", json={"status": "resolved"}, headers=admin).status_code == 200
    d = client.get(f"/api/incidents/{iid}", headers=admin).json(); assert d["resolved_at"] and len(d["history"]) >= 3 and d["events"]
    assert client.patch(f"/api/incidents/{iid}", json={"status": "bogus"}, headers=admin).status_code == 422
def test_ai_fallback_and_dashboard(client, admin):
    r = client.post("/api/ai/analyze", json={"question": "what is happening?"}, headers=admin).json(); assert r["source"] in ("fallback", "llm") and "actions" in r
    assert client.get("/api/dashboard", headers=admin).json()["kpis"]["total_events"] > 0
    assert client.get("/api/analytics/export.csv?kind=events", headers=admin).headers["content-type"].startswith("text/csv")
