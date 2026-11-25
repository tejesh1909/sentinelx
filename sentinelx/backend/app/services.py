"""Ingestion/normalization, detection, risk scoring, correlation. Rule-based and deliberately simple:
it demonstrates the pipeline on controlled data and is NOT complete real-world attack detection."""
import hashlib, ipaddress, json, os, datetime as dt
import httpx
from sqlalchemy import select, func
from .core import now
from .models import *

SEV = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SOURCES = {"application", "api_gateway", "authentication", "cloud", "server"}
ALIASES = {"timestamp": ["timestamp", "time", "@timestamp", "eventTime", "ts"],
           "event_type": ["event_type", "type", "event"], "ip": ["ip", "ip_address", "src_ip", "client_ip"],
           "user_identity": ["user_identity", "user", "username", "actor"], "resource": ["resource", "path", "url", "target"],
           "action": ["action", "method", "operation"], "status": ["status", "result", "outcome", "status_code"],
           "severity": ["severity", "level"], "event_id": ["event_id", "id", "eventID"]}
SENSITIVE = {"/admin": 10, "secrets": 10, "payroll": 10, "prod-db": 10, "customers/export": 8, "users/export": 8, "/billing": 6}
def asset_score(res): r = (res or "").lower(); return max([v for k, v in SENSITIVE.items() if k in r] or [0])
# Indicative (approximate) ATT&CK mapping: rule -> (technique id, name, tactic)
MITRE = {"failed_login_burst": ("T1110", "Brute Force", "Credential Access"), "unusual_ip": ("T1078", "Valid Accounts", "Initial Access"),
         "api_probing": ("T1595", "Active Scanning", "Reconnaissance"), "unauthorized_access": ("T1190", "Exploit Public-Facing App (approx.)", "Initial Access"),
         "privilege_escalation": ("T1098", "Account Manipulation", "Privilege Escalation"), "sensitive_access": ("T1213", "Data from Information Repositories", "Collection"),
         "request_flood": ("T1498", "Network Denial of Service", "Impact"), "admin_offhours": ("T1078.004", "Valid Accounts: Cloud (approx.)", "Defense Evasion"),
         "volume_anomaly": ("T1071", "Application Layer Protocol (approx.)", "Command and Control")}
PLAYBOOKS = {  # manual recommendations only; nothing is executed automatically
 "failed_login_burst": ["Contact the account owner to confirm", "Force password reset and revoke active sessions", "Require MFA", "Rate-limit or block the source IP"],
 "unusual_ip": ["Verify the login location with the user", "Revoke sessions from the new IP", "Review what the session accessed"],
 "api_probing": ["Block or challenge the source IP at the gateway", "Review gateway/WAF rules for the probed paths", "Check for any successful (2xx) requests from the IP"],
 "unauthorized_access": ["Review the principal's permissions", "Confirm the denied access was not a misconfiguration"],
 "privilege_escalation": ["Verify the change was approved", "Revert the role/policy if unapproved", "Audit actions taken with the elevated privileges"],
 "sensitive_access": ["Identify what data was read/exported", "Assess data-breach notification obligations", "Restrict access to the resource pending review"],
 "request_flood": ["Apply rate limiting / WAF rule for the source", "Check service health and capacity"],
 "admin_offhours": ["Confirm with the administrator", "Review other admin actions in the same period"],
 "volume_anomaly": ["Check for automation, scraping or exfiltration", "Compare with the user's normal activity"]}
def level(s): return "low" if s < 30 else "medium" if s < 60 else "high" if s < 80 else "critical"

# ---------- normalization ----------
def from_cloudtrail(r):
    ui = r.get("userIdentity") or {}; n = r.get("eventName", "")
    et = "login" if n == "ConsoleLogin" else "role_change" if ("Policy" in n or "Role" in n) else "admin_action" if n.startswith(("Create", "Delete", "Put")) else "api_request"
    st = "denied" if r.get("errorCode") in ("AccessDenied", "UnauthorizedOperation") else "failure" if (r.get("responseElements") or {}).get("ConsoleLogin") == "Failure" else "success"
    return {"timestamp": r["eventTime"], "event_type": et, "ip": r.get("sourceIPAddress"), "user_identity": ui.get("userName") or ui.get("arn"),
            "resource": r.get("eventSource"), "action": n.lower(), "status": st, "event_id": r.get("eventID"), "source": "cloud"}
def _pick(raw, k):
    for a in ALIASES[k]:
        if raw.get(a) not in (None, ""): return raw[a]
def _ts(v):
    t = dt.datetime.fromtimestamp(v / 1000 if v > 1e11 else v, dt.timezone.utc) if isinstance(v, (int, float)) else dt.datetime.fromisoformat(str(v).strip().replace("Z", "+00:00"))
    return t.astimezone(dt.timezone.utc).replace(tzinfo=None) if t.tzinfo else t
def _status(v):
    s = str(v or "success").lower()
    if s in ("success", "ok", "allowed", "200", "201", "204", "succeeded"): return "success"
    if s in ("denied", "403", "forbidden", "unauthorized"): return "denied"
    if s in ("failure", "failed", "fail", "401", "error") or s[:1] in "45" and s.isdigit(): return "failure"
    return s[:32]
def normalize(raw, default_source=None):
    if not isinstance(raw, dict): raise ValueError("event must be an object")
    orig = raw
    if "eventName" in raw and "eventTime" in raw: raw = from_cloudtrail(raw)
    f = {k: _pick(raw, k) for k in ALIASES}
    if not f["timestamp"]: raise ValueError("missing timestamp")
    if not f["event_type"]: raise ValueError("missing event_type")
    ip = str(ipaddress.ip_address(str(f["ip"]).strip())) if f["ip"] else None
    st = _status(f["status"]); sev = str(f["severity"] or "").lower()
    if sev not in SEV: sev = "medium" if st == "denied" else "low"
    src = str(raw.get("source") or default_source or "application").lower()
    if src not in SOURCES: raise ValueError(f"unknown source '{src[:30]}'")
    s = lambda k, n: (str(f[k])[:n] if f[k] else None)
    if len(json.dumps(orig, default=str)) > 8192: raise ValueError("raw event too large")
    return dict(event_id=s("event_id", 128), timestamp=_ts(f["timestamp"]), source=src, event_type=str(f["event_type"]).lower()[:64], ip=ip,
                user_identity=s("user_identity", 128), resource=s("resource", 512), action=(s("action", 64) or "").lower() or None,
                status=st, severity=sev, raw=json.loads(json.dumps(orig, default=str)))
def fingerprint(n):
    return hashlib.sha256("|".join(str(n[k]) for k in ("source", "timestamp", "event_type", "ip", "user_identity", "resource", "action", "status", "event_id")).encode()).hexdigest()

def ingest(db, raws, source=None):
    res = {"accepted": 0, "duplicates": 0, "invalid": [], "threats": 0}; new = []; seen = set()
    for i, r in enumerate(raws):
        try: n = normalize(r, source)
        except (ValueError, TypeError, KeyError, OverflowError, OSError) as ex:
            res["invalid"].append({"index": i, "error": str(ex)[:200]}); continue
        fp = fingerprint(n)
        if fp in seen or db.scalar(select(Event.id).where(Event.fingerprint == fp)): res["duplicates"] += 1; continue
        seen.add(fp); e = Event(fingerprint=fp, **n); db.add(e); new.append(e)
    db.flush(); new.sort(key=lambda e: e.timestamp)
    for e in new: res["threats"] += detect(db, e)
    db.flush(); correlate(db); db.commit(); res["accepted"] = len(new)
    return res

# ---------- detection ----------
M = lambda m: dt.timedelta(minutes=m)
def _cnt(db, *c): return db.scalar(select(func.count()).select_from(Event).where(*c)) or 0
def d_failed(db, e, p):
    if e.event_type != "login" or e.status != "failure" or not e.user_identity: return
    n = _cnt(db, Event.event_type == "login", Event.status == "failure", Event.user_identity == e.user_identity, Event.timestamp <= e.timestamp, Event.timestamp >= e.timestamp - M(p["window_min"]))
    if n >= p["threshold"]: return f"{n} failed logins for '{e.user_identity}' within {p['window_min']} minutes", min(.95, .5 + .05 * n)
def d_unusual_ip(db, e, p):
    if e.event_type != "login" or e.status != "success" or not (e.user_identity and e.ip): return
    base = [Event.event_type == "login", Event.status == "success", Event.user_identity == e.user_identity, Event.timestamp < e.timestamp]
    n = _cnt(db, *base)
    if n < p["min_history"] or _cnt(db, *base, Event.ip == e.ip): return
    fails = _cnt(db, Event.event_type == "login", Event.status == "failure", Event.user_identity == e.user_identity, Event.timestamp < e.timestamp, Event.timestamp >= e.timestamp - M(30))
    return f"Successful login for '{e.user_identity}' from {e.ip}, not seen in {n} earlier successful logins" + (f"; {fails} failed logins in the prior 30 min" if fails else ""), .65 + (.2 if fails >= 3 else 0)
def d_probe(db, e, p):
    if e.event_type != "api_request" or e.status not in ("denied", "failure") or not e.ip: return
    n = db.scalar(select(func.count(func.distinct(Event.resource))).where(Event.ip == e.ip, Event.event_type == "api_request", Event.status.in_(["denied", "failure"]), Event.timestamp <= e.timestamp, Event.timestamp >= e.timestamp - M(p["window_min"]))) or 0
    if n >= p["threshold"]: return f"{e.ip} hit {n} distinct resources with denied/failed requests in {p['window_min']} min", .7
def d_unauth(db, e, p):
    if e.status == "denied" and e.event_type in ("api_request", "resource_access"): return f"Access denied for {e.user_identity or e.ip} on {e.resource}", .7
def d_priv(db, e, p):
    if (e.action or "") in p["actions"] or e.event_type == "role_change": return f"Privilege change '{e.action}' on {e.resource} by {e.user_identity}", .8 if e.status == "success" else .6
def d_sens(db, e, p):
    if e.status == "success" and e.action in ("read", "download", "export", "get") and asset_score(e.resource) >= 8: return f"'{e.user_identity}' accessed sensitive resource {e.resource}", .45
def d_flood(db, e, p):
    if e.event_type != "api_request" or not e.ip: return
    n = _cnt(db, Event.event_type == "api_request", Event.ip == e.ip, Event.timestamp <= e.timestamp, Event.timestamp > e.timestamp - M(p["window_min"]))
    if n >= p["threshold"]: return f"{e.ip} made {n} requests in {p['window_min']} minute(s)", .75
def d_offhours(db, e, p):
    if e.event_type == "admin_action" and not (p["start_hour"] <= e.timestamp.hour < p["end_hour"]): return f"Admin action '{e.action}' by {e.user_identity} at {e.timestamp:%H:%M} UTC (outside business hours)", .55
def d_volume(db, e, p):
    """Statistical baseline: events per user in a window vs that user's historical mean (Poisson-style z-score). Basic, not ML."""
    if not e.user_identity: return
    w = p["window_min"]; hi = e.timestamp; u = Event.user_identity == e.user_identity
    n = _cnt(db, u, Event.timestamp <= hi, Event.timestamp > hi - M(w))
    if n < p["min_count"]: return
    total = _cnt(db, u, Event.timestamp < hi - M(w), Event.timestamp >= hi - dt.timedelta(days=p["history_days"]))
    mean = total / (p["history_days"] * 24 * 60 / w); z = (n - mean) / max(mean ** .5, 1)
    if z >= p["z"]: return f"{n} events from '{e.user_identity}' in {w} min vs baseline {mean:.2f} (z={z:.1f})", min(.9, .5 + z / 40)
DETECTORS = {"volume_anomaly": d_volume, "failed_login_burst": d_failed, "unusual_ip": d_unusual_ip, "api_probing": d_probe, "unauthorized_access": d_unauth,
             "privilege_escalation": d_priv, "sensitive_access": d_sens, "request_flood": d_flood, "admin_offhours": d_offhours}
DEFAULT_RULES = [
 ("failed_login_burst", "Multiple failed logins", "Failed logins for one user inside a time window", {"threshold": 5, "window_min": 10, "severity": "high"}),
 ("unusual_ip", "Login from unusual IP", "Successful login from an IP not in the user's history", {"min_history": 3, "severity": "medium"}),
 ("api_probing", "Suspicious API request pattern", "Many distinct denied/failed resources from one IP", {"threshold": 6, "window_min": 10, "severity": "medium"}),
 ("unauthorized_access", "Unauthorized access attempt", "Request denied (403)", {"window_min": 10, "severity": "medium"}),
 ("privilege_escalation", "Privilege escalation indicator", "Role or permission grants", {"actions": ["grant_role", "add_to_admin", "attach_policy", "attachuserpolicy", "attachrolepolicy", "set_admin"], "severity": "high"}),
 ("sensitive_access", "Unusual access to sensitive resource", "Read/export of high-sensitivity resources", {"window_min": 10, "severity": "medium"}),
 ("request_flood", "Abnormal request frequency", "High request count from one IP", {"threshold": 50, "window_min": 1, "severity": "high"}),
 ("volume_anomaly", "Anomalous event volume", "Per-user volume far above own baseline (z-score)", {"window_min": 10, "min_count": 15, "history_days": 5, "z": 4.0, "severity": "medium"}),
 ("admin_offhours", "Suspicious administrative activity", "Admin actions outside business hours", {"start_hour": 6, "end_hour": 22, "window_min": 60, "severity": "medium"})]

def detect(db, e):
    made = 0
    for rule in db.scalars(select(Rule).where(Rule.enabled.is_(True))):
        fn = DETECTORS.get(rule.key); hitr = fn and fn(db, e, rule.params)
        if not hitr: continue
        desc, conf = hitr; w = rule.params.get("window_min", 10)
        q = select(Threat.id).join(Event, Event.id == Threat.event_id).where(Threat.rule_key == rule.key, Event.timestamp <= e.timestamp, Event.timestamp >= e.timestamp - M(w))
        q = q.where(Threat.user_identity == e.user_identity) if e.user_identity else q.where(Threat.ip == e.ip)
        if db.scalar(q.limit(1)): continue
        t = Threat(category=rule.name, description=desc, event_id=e.id, severity=rule.params.get("severity", "medium"), confidence=round(conf, 2),
                   user_identity=e.user_identity, resource=e.resource, ip=e.ip, rule_key=rule.key)
        db.add(t); db.flush(); score_threat(db, t, e); made += 1
    return made

# ---------- risk scoring ----------
RISK = {"severity_base": {"low": 10, "medium": 30, "high": 55, "critical": 75}, "freq_per_repeat": 3, "freq_cap": 12,
        "privilege": {"admin": 10, "service": 5, "user": 0}, "repeat_bonus": 8, "confidence_floor": .6,
        "incident_per_extra_category": 10, "incident_sensitive_bonus": 10}
if os.getenv("RISK_CONFIG_JSON"):
    try: RISK.update(json.loads(os.environ["RISK_CONFIG_JSON"]))
    except ValueError: pass
def user_priv(e):
    r = str((e.raw or {}).get("role", "")).lower(); u = (e.user_identity or "").lower()
    return "admin" if "admin" in (r + u) else "service" if u.startswith(("svc", "service")) or r == "service" else "user"
def compute_score(sev, conf, prior_same, asset, priv, repeat):
    c = RISK
    parts = [("Threat severity", c["severity_base"][sev], f"'{sev}' severity base"),
             ("Event frequency", min(c["freq_cap"], c["freq_per_repeat"] * prior_same), f"{prior_same} earlier similar threat(s) in 24h"),
             ("Asset sensitivity", asset, "sensitivity of the affected resource (0-10)"),
             ("User privilege", c["privilege"][priv], f"'{priv}' level identity"),
             ("Repeated suspicious activity", c["repeat_bonus"] if repeat else 0, "other threat categories for the same identity in 24h" if repeat else "none")]
    raw = sum(p[1] for p in parts); mult = c["confidence_floor"] + (1 - c["confidence_floor"]) * conf
    score = max(0, min(100, round(raw * mult)))
    factors = [{"name": n, "points": p, "note": m} for n, p, m in parts] + [{"name": "Detection confidence", "points": 0, "note": f"x{mult:.2f} multiplier (confidence {conf:.2f})"}]
    expl = "; ".join(f"{f['name']} +{f['points']}" for f in factors[:-1] if f["points"]) + f"; {factors[-1]['note']} => {score}/100 ({level(score)})"
    return score, factors, expl
def score_threat(db, t, e):
    since = e.timestamp - dt.timedelta(hours=24); key = (Threat.user_identity == t.user_identity) if t.user_identity else (Threat.ip == t.ip)
    base = [Threat.id != t.id, key, Threat.detected_at >= since - dt.timedelta(days=365)]
    same = db.scalar(select(func.count()).select_from(Threat).join(Event, Event.id == Threat.event_id).where(*base, Threat.category == t.category, Event.timestamp >= since, Event.timestamp <= e.timestamp)) or 0
    oth = db.scalar(select(func.count()).select_from(Threat).join(Event, Event.id == Threat.event_id).where(*base, Threat.category != t.category, Event.timestamp >= since, Event.timestamp <= e.timestamp)) or 0
    s, f, x = compute_score(t.severity, t.confidence, same, asset_score(t.resource), user_priv(e), oth > 0)
    db.add(RiskAssessment(threat_id=t.id, score=s, level=level(s), factors=f, explanation=x))

# ---------- correlation ----------
def _add_note(db, inc_id, kind, body, author=None): db.add(IncidentNote(incident_id=inc_id, author_id=author, kind=kind, body=body))
def score_incident(db, inc):
    ts = db.scalars(select(Threat).where(Threat.incident_id == inc.id)).all()
    if not ts: return
    ras = {r.threat_id: r for r in db.scalars(select(RiskAssessment).where(RiskAssessment.threat_id.in_([t.id for t in ts])))}
    top = max(ras[t.id].score for t in ts if t.id in ras); cats = {t.category for t in ts}
    sens = any(asset_score(t.resource) >= 8 for t in ts); c = RISK
    s = min(100, top + c["incident_per_extra_category"] * (len(cats) - 1) + (c["incident_sensitive_bonus"] if sens else 0))
    f = [{"name": "Highest threat score", "points": top, "note": "max over linked threats"},
         {"name": "Distinct threat categories", "points": c["incident_per_extra_category"] * (len(cats) - 1), "note": f"{len(cats)}: " + ", ".join(sorted(cats))},
         {"name": "Sensitive asset involved", "points": c["incident_sensitive_bonus"] if sens else 0, "note": "high-sensitivity resource touched" if sens else "none"}]
    x = f"Incident score {s}/100 ({level(s)}): strongest linked threat {top}, +{f[1]['points']} for {len(cats)} correlated categories" + (f", +{f[2]['points']} for sensitive asset access" if sens else "")
    inc.risk_score, inc.risk_level = s, level(s)
    db.add(RiskAssessment(incident_id=inc.id, score=s, level=level(s), factors=f, explanation=x))
def _link_events(db, inc, key, val, lo, hi, w):
    col = {"user_identity": Event.user_identity, "ip": Event.ip, "resource": Event.resource}[key]
    have = set(db.scalars(select(IncidentEvent.event_id).where(IncidentEvent.incident_id == inc.id)))
    for eid in db.scalars(select(Event.id).where(col == val, Event.timestamp >= lo - M(w), Event.timestamp <= hi + M(w)).limit(300)):
        if eid not in have: db.add(IncidentEvent(incident_id=inc.id, event_id=eid))
def correlate(db, window=60):
    """Cluster un-assigned threats by user, IP, then resource inside a time window; >=2 categories => incident."""
    for key in ("user_identity", "ip", "resource"):
        rows = db.execute(select(Threat, Event.timestamp).join(Event, Event.id == Threat.event_id).where(Threat.incident_id.is_(None)).order_by(Event.timestamp)).all()
        groups = {}
        for t, ts in rows:
            v = getattr(t, key)
            if v: groups.setdefault(v, []).append((t, ts))
        for val, items in groups.items():
            cl = [items[0:1]]
            for it in items[1:]:
                (cl[-1].append(it) if it[1] - cl[-1][-1][1] <= M(window) else cl.append([it]))
            for c in cl:
                cats = {t.category for t, _ in c}
                if len(cats) < 2 and not (key == "resource" and len({t.ip for t, _ in c}) >= 2): continue
                ck = f"{key}:{val}"
                inc = db.scalar(select(Incident).where(Incident.correlation_key == ck, Incident.status.in_(["new", "investigating", "in_progress"])))
                if not inc:
                    inc = Incident(title=f"Correlated activity on {val}: " + ", ".join(sorted(cats)), correlation_key=ck); db.add(inc); db.flush()
                    _add_note(db, inc.id, "system", f"Incident created by correlation engine (key={ck}, window={window} min, {len(c)} threats).")
                for t, _ in c: t.incident_id = inc.id
                db.flush(); _link_events(db, inc, key, val, c[0][1], c[-1][1], window); score_incident(db, inc)
                inc.priority = inc.risk_level; db.flush(); notify(inc)
def incident_from_threat(db, t, user):
    if t.incident_id: return db.get(Incident, t.incident_id)
    inc = Incident(title=f"{t.category}: {t.user_identity or t.ip}", correlation_key=None); db.add(inc); db.flush()
    t.incident_id = inc.id; e = db.get(Event, t.event_id); db.add(IncidentEvent(incident_id=inc.id, event_id=e.id)); db.flush()
    score_incident(db, inc); inc.priority = inc.risk_level
    _add_note(db, inc.id, "system", f"Incident created manually from threat {t.id}", user.id); return inc

def notify(inc):
    """Slack-compatible webhook for new critical incidents (WEBHOOK_URL). Best effort."""
    url = os.getenv("WEBHOOK_URL")
    if inc.risk_level != "critical" or inc.notified or not url: return
    inc.notified = True
    try: httpx.post(url, json={"text": f"[SentinelX] CRITICAL incident: {inc.title} (risk {inc.risk_score}/100)"}, timeout=5)
    except Exception: pass
def ingest_job(raws, source=None):
    """RQ worker entrypoint (queue 'ingest')."""
    from .core import SessionLocal
    with SessionLocal() as db:
        r = ingest(db, raws, source); return {k: (v if k != "invalid" else len(v)) for k, v in r.items()}
