import datetime as dt, pyotp
from tests.test_core import ev
T = dt.datetime(2026, 2, 1, 9)
def test_volume_anomaly(client, admin):
    evs = [{"timestamp": (T + dt.timedelta(seconds=5 * i)).isoformat(), "event_type": "api_request", "user": "burst1", "ip": "10.5.5.5", "resource": f"/r/{i}", "status": "200", "source": "api_gateway"} for i in range(25)]
    client.post("/api/events/ingest", json={"events": evs}, headers=admin)
    th = client.get("/api/threats?size=100", headers=admin).json()["items"]
    t = [x for x in th if x["user"] == "burst1" and x["category"] == "Anomalous event volume"]; assert t and t[0]["mitre"]["id"] == "T1071"
def test_mitre_and_ip(client, admin):
    assert any(x["technique"] == "T1110" for x in client.get("/api/mitre", headers=admin).json())
    assert client.get("/api/ip/203.0.113.5", headers=admin).json()["geo"]; assert client.get("/api/ip/nope", headers=admin).status_code == 400
def test_lockout(client):
    client.post("/api/auth/register", json={"email": "lock@x.co", "full_name": "L", "password": "longenoughpw1"})
    for _ in range(5): assert client.post("/api/auth/login", json={"email": "lock@x.co", "password": "bad"}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "lock@x.co", "password": "longenoughpw1"}).status_code == 423
def test_mfa_flow(client):
    client.post("/api/auth/register", json={"email": "mfa@x.co", "full_name": "M", "password": "longenoughpw1"})
    h = {"Authorization": "Bearer " + client.post("/api/auth/login", json={"email": "mfa@x.co", "password": "longenoughpw1"}).json()["access_token"]}
    s = client.post("/api/mfa/setup", headers=h).json()["secret"]; assert client.post("/api/mfa/enable", json={"code": "000000"}, headers=h).status_code == 400
    assert client.post("/api/mfa/enable", json={"code": pyotp.TOTP(s).now()}, headers=h).json()["mfa_enabled"]
    assert client.post("/api/auth/login", json={"email": "mfa@x.co", "password": "longenoughpw1"}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "mfa@x.co", "password": "longenoughpw1", "otp": pyotp.TOTP(s).now()}).status_code == 200
def test_report_escapes_html(client, admin):
    inc = client.get("/api/incidents?size=1", headers=admin).json()["items"]
    if inc:
        r = client.get(f"/api/incidents/{inc[0]['id']}/report", headers=admin); assert r.status_code == 200 and "<script" not in r.text and "Incident report" in r.text
