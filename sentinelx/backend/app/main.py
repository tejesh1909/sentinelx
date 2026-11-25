import csv, html, io, ipaddress, json, os, secrets, time, datetime as dt
import httpx, pyotp
from typing import Literal
from fastapi import BackgroundTasks, FastAPI, Query, Depends, HTTPException, Request, UploadFile, File
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import select, func, or_, desc
from starlette.exceptions import HTTPException as SHTTP
from . import ai, services as sv
from .core import SessionLocal, hash_pw, verify_pw, make_token, decode, hit, now
from .models import *

app = FastAPI(title="SentinelX API", version="1.0", docs_url="/api/docs", openapi_url="/api/openapi.json")
RL_OFF = os.getenv("RATE_LIMIT_DISABLED") == "1"; MAX_UPLOAD = 2 * 1024 * 1024
ST = ["new", "investigating", "in_progress", "resolved", "closed"]; PRI = ["low", "medium", "high", "critical"]

def err(code, msg, **x): return JSONResponse({"error": {"code": code, "message": msg, **x}}, status_code=code)
@app.exception_handler(SHTTP)
async def _h(r, e): return err(e.status_code, str(e.detail))
@app.exception_handler(RequestValidationError)
async def _v(r, e): return err(422, "Validation failed", details=[{"loc": [str(i) for i in x["loc"]], "msg": x["msg"]} for x in e.errors()])
@app.middleware("http")
async def limiter(req: Request, call):
    if not RL_OFF and req.url.path.startswith("/api") and not req.url.path.startswith("/api/docs"):
        strict = req.url.path in ("/api/auth/login", "/api/auth/register"); ip = req.client.host if req.client else "?"
        if not hit(f"{ip}:{req.url.path if strict else 'g'}", 10 if strict else 300): return err(429, "Rate limit exceeded")
    return await call(req)

def get_db():
    with SessionLocal() as db: yield db
bearer = HTTPBearer(auto_error=False)
def current_user(c=Depends(bearer), db=Depends(get_db)):
    try:
        p = decode(c.credentials)
        assert p["type"] == "access"
    except Exception: raise HTTPException(401, "Invalid or missing token")
    u = db.get(User, p["sub"])
    if not u or not u.is_active: raise HTTPException(401, "Account disabled or not found")
    return u
def require(*roles):
    def dep(u=Depends(current_user)):
        if u.role.name not in roles: raise HTTPException(403, "Insufficient permissions")
        return u
    return dep
ANY, WRITE, ADMIN = Depends(current_user), Depends(require("admin", "analyst")), Depends(require("admin"))
def audit(db, u, action, target=None, detail=None, req=None):
    db.add(AuditLog(user_id=u.id if u else None, action=action, target=target, detail=detail, ip=req.client.host if req and req.client else None))

def su(u): return {"id": u.id, "email": u.email, "full_name": u.full_name, "role": u.role.name, "is_active": u.is_active, "must_change_password": u.must_change_password, "mfa_enabled": u.mfa_enabled}
def se(e): return {"id": e.id, "event_id": e.event_id, "timestamp": e.timestamp.isoformat(), "source": e.source, "event_type": e.event_type, "ip": e.ip, "user": e.user_identity, "resource": e.resource, "action": e.action, "status": e.status, "severity": e.severity, "raw": e.raw}
def rmap(db, ids):
    return {r.threat_id: r for r in db.scalars(select(RiskAssessment).where(RiskAssessment.threat_id.in_(ids)))} if ids else {}
def st(t, rm):
    r = rm.get(t.id); return {"id": t.id, "category": t.category, "description": t.description, "severity": t.severity, "confidence": t.confidence, "detected_at": t.detected_at.isoformat(),
        "user": t.user_identity, "resource": t.resource, "ip": t.ip, "event_id": t.event_id, "incident_id": t.incident_id, "risk_score": r.score if r else None, "risk_level": r.level if r else None,
        "mitre": ({"id": m[0], "name": m[1], "tactic": m[2]} if (m := sv.MITRE.get(t.rule_key)) else None)}
def si(i): return {"id": i.id, "title": i.title, "status": i.status, "priority": i.priority, "assignee_id": i.assignee_id, "risk_score": i.risk_score, "risk_level": i.risk_level, "summary": i.summary, "created_at": i.created_at.isoformat(), "resolved_at": i.resolved_at.isoformat() if i.resolved_at else None}
def page(db, q, ser, p, size):
    size = min(max(size, 1), 100); total = db.scalar(select(func.count()).select_from(q.order_by(None).subquery()))
    return {"items": [ser(x) for x in db.scalars(q.offset((max(p, 1) - 1) * size).limit(size))], "total": total, "page": p, "size": size}
def pdate(s):
    try: return dt.datetime.fromisoformat(s)
    except ValueError: raise HTTPException(400, "Dates must be ISO format (YYYY-MM-DD)")
def ev_conds(df, to, sev, src):
    c = []
    if df: c.append(Event.timestamp >= pdate(df))
    if to: c.append(Event.timestamp < pdate(to) + dt.timedelta(days=1))
    if sev: c.append(Event.severity == sev)
    if src: c.append(Event.source == src)
    return c

# ---------- auth ----------
class Reg(BaseModel): email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=255); full_name: str = Field(min_length=1, max_length=120); password: str = Field(min_length=10, max_length=128)
class Login(BaseModel): email: str; password: str; otp: str | None = None
class Refresh(BaseModel): refresh_token: str
def issue(db, u):
    s = AuthSession(id=secrets.token_hex(16), user_id=u.id); db.add(s); db.commit()
    return {"access_token": make_token(u.id, "access", 15), "refresh_token": make_token(u.id, "refresh", 60 * 24 * 7, s.id), "user": su(u)}
@app.post("/api/auth/register", status_code=201)
def register(b: Reg, req: Request, db=Depends(get_db)):
    if os.getenv("ALLOW_REGISTRATION", "1") != "1": raise HTTPException(403, "Registration disabled")
    if db.scalar(select(User).where(User.email == b.email.lower())): raise HTTPException(409, "Email already registered")
    u = User(email=b.email.lower(), full_name=b.full_name, password_hash=hash_pw(b.password), role_id=db.scalar(select(Role.id).where(Role.name == "analyst")))
    db.add(u); audit(db, u, "register", u.id, req=req); db.commit(); return su(u)
@app.post("/api/auth/login")
def login(b: Login, req: Request, db=Depends(get_db)):
    u = db.scalar(select(User).where(User.email == b.email.lower()))
    if u and u.locked_until and u.locked_until > now(): raise HTTPException(423, "Account temporarily locked; try again later")
    ok = bool(u and u.is_active and verify_pw(u.password_hash, b.password))
    if ok and u.mfa_enabled:
        if not b.otp: raise HTTPException(401, "MFA code required")
        ok = pyotp.TOTP(u.mfa_secret).verify(b.otp, valid_window=1)
    if not ok:
        if u:
            u.failed_attempts = (u.failed_attempts or 0) + 1
            if u.failed_attempts >= 5: u.locked_until = now() + dt.timedelta(minutes=15); u.failed_attempts = 0
        audit(db, None, "login_failed", b.email[:100], req=req); db.commit(); raise HTTPException(401, "Invalid credentials")
    u.failed_attempts = 0; u.locked_until = None
    audit(db, u, "login", u.id, req=req); return issue(db, u)
@app.post("/api/auth/refresh")
def refresh(b: Refresh, db=Depends(get_db)):
    try:
        p = decode(b.refresh_token); assert p["type"] == "refresh"
    except Exception: raise HTTPException(401, "Invalid refresh token")
    s = db.get(AuthSession, p["jti"]); u = db.get(User, p["sub"])
    if not s or s.revoked or not u or not u.is_active: raise HTTPException(401, "Session expired")
    s.revoked = True; return issue(db, u)
@app.post("/api/auth/logout")
def logout(b: Refresh, db=Depends(get_db)):
    try:
        s = db.get(AuthSession, decode(b.refresh_token)["jti"])
        if s: s.revoked = True; db.commit()
    except Exception: pass
    return {"ok": True}
class Prof(BaseModel): full_name: str | None = Field(None, max_length=120); current_password: str | None = None; new_password: str | None = Field(None, min_length=10, max_length=128)
@app.get("/api/me")
def me(u=ANY): return su(u)
@app.patch("/api/me")
def upd_me(b: Prof, req: Request, u=ANY, db=Depends(get_db)):
    if b.full_name: u.full_name = b.full_name
    if b.new_password:
        if not b.current_password or not verify_pw(u.password_hash, b.current_password): raise HTTPException(400, "Current password incorrect")
        u.password_hash = hash_pw(b.new_password); u.must_change_password = False; audit(db, u, "password_change", u.id, req=req)
    db.commit(); return su(u)
@app.get("/api/users")
def users(u=ADMIN, db=Depends(get_db)): return [su(x) for x in db.scalars(select(User).order_by(User.created_at))]
@app.get("/api/users-lite")
def users_lite(u=ANY, db=Depends(get_db)): return [{"id": x.id, "full_name": x.full_name} for x in db.scalars(select(User).where(User.is_active.is_(True)))]
class UserPatch(BaseModel): role: Literal["admin", "analyst"] | None = None; is_active: bool | None = None
@app.patch("/api/users/{uid}")
def patch_user(uid: str, b: UserPatch, req: Request, u=ADMIN, db=Depends(get_db)):
    t = db.get(User, uid)
    if not t: raise HTTPException(404, "User not found")
    if t.id == u.id: raise HTTPException(400, "You cannot modify your own role/status")
    if b.role: t.role_id = db.scalar(select(Role.id).where(Role.name == b.role)); db.flush()
    if b.is_active is not None: t.is_active = b.is_active
    audit(db, u, "user_update", uid, b.model_dump(exclude_none=True), req); db.commit(); db.refresh(t); return su(t)

# ---------- events ----------
class IngestIn(BaseModel): source: str | None = None; events: list[dict] = Field(max_length=1000)
@app.post("/api/events/ingest")
def ingest_api(b: IngestIn, req: Request, async_mode: bool = False, u=WRITE, db=Depends(get_db)):
    if async_mode:  # queue to the RQ worker if Redis is available, else fall through to synchronous processing
        try:
            from redis import Redis; from rq import Queue
            j = Queue("ingest", connection=Redis.from_url(os.environ["REDIS_URL"], socket_timeout=1)).enqueue("app.services.ingest_job", b.events, b.source, job_timeout=300)
            audit(db, u, "ingest_queued", j.id, req=req); db.commit(); return JSONResponse({"queued": True, "job_id": j.id}, status_code=202)
        except Exception: pass
    r = sv.ingest(db, b.events, b.source); audit(db, u, "ingest", None, {k: (v if k != "invalid" else len(v)) for k, v in r.items()}, req); db.commit(); return r
@app.post("/api/events/upload")
async def upload(req: Request, file: UploadFile = File(...), source: str | None = None, u=WRITE, db=Depends(get_db)):
    name = (file.filename or "").lower()
    if not name.endswith((".json", ".csv")): raise HTTPException(415, "Only .json or .csv files are accepted")
    data = await file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD: raise HTTPException(413, "File exceeds 2 MB limit")
    try:
        text = data.decode("utf-8-sig"); rows = json.loads(text) if name.endswith(".json") else list(csv.DictReader(io.StringIO(text)))
    except (UnicodeDecodeError, ValueError, csv.Error): raise HTTPException(400, "Could not parse file (UTF-8 JSON array or CSV with header required)")
    if isinstance(rows, dict): rows = rows.get("events", [rows])
    if not isinstance(rows, list) or len(rows) > 5000: raise HTTPException(400, "Expected a list of at most 5000 events")
    r = sv.ingest(db, rows, source); audit(db, u, "upload", name[:100], {"accepted": r["accepted"]}, req); db.commit(); return r
@app.get("/api/events")
def events(q: str | None = None, severity: str | None = None, source: str | None = None, date_from: str | None = None, date_to: str | None = None, page_: int = Query(1, alias="page"), size: int = 20, u=ANY, db=Depends(get_db)):
    qq = select(Event).where(*ev_conds(date_from, date_to, severity, source)).order_by(desc(Event.timestamp))
    if q:
        l = f"%{q[:100]}%"; qq = qq.where(or_(Event.user_identity.ilike(l), Event.ip.ilike(l), Event.resource.ilike(l), Event.event_type.ilike(l)))
    return page(db, qq, se, page_, size)

# ---------- threats / rules / risk ----------
@app.get("/api/threats")
def threats(severity: str | None = None, min_severity: str | None = None, page_: int = Query(1, alias="page"), size: int = 20, u=ANY, db=Depends(get_db)):
    qq = select(Threat).order_by(desc(Threat.detected_at), desc(Threat.id))
    if severity: qq = qq.where(Threat.severity == severity)
    if min_severity in sv.SEV: qq = qq.where(Threat.severity.in_([k for k, v in sv.SEV.items() if v >= sv.SEV[min_severity]]))
    total = db.scalar(select(func.count()).select_from(qq.order_by(None).subquery())); size = min(max(size, 1), 100)
    ts = db.scalars(qq.offset((max(page_, 1) - 1) * size).limit(size)).all(); rm = rmap(db, [t.id for t in ts])
    return {"items": [st(t, rm) for t in ts], "total": total, "page": page_, "size": size}
@app.post("/api/threats/{tid}/incident", status_code=201)
def threat_incident(tid: str, req: Request, u=WRITE, db=Depends(get_db)):
    t = db.get(Threat, tid)
    if not t: raise HTTPException(404, "Threat not found")
    i = sv.incident_from_threat(db, t, u); audit(db, u, "incident_create", i.id, req=req); db.commit(); return si(i)
@app.get("/api/rules")
def rules(u=ANY, db=Depends(get_db)): return [{"id": r.id, "key": r.key, "name": r.name, "description": r.description, "enabled": r.enabled, "params": r.params} for r in db.scalars(select(Rule).order_by(Rule.id))]
class RulePatch(BaseModel): enabled: bool | None = None; params: dict | None = None
@app.patch("/api/rules/{rid}")
def patch_rule(rid: int, b: RulePatch, req: Request, u=ADMIN, db=Depends(get_db)):
    r = db.get(Rule, rid)
    if not r: raise HTTPException(404, "Rule not found")
    if b.enabled is not None: r.enabled = b.enabled
    if b.params is not None:
        for k, v in b.params.items():
            if k not in r.params or type(v) is not type(r.params[k]): raise HTTPException(400, f"Invalid parameter '{k}'")
        r.params = {**r.params, **b.params}
    audit(db, u, "rule_update", r.key, b.model_dump(exclude_none=True), req); db.commit(); return {"id": r.id, "enabled": r.enabled, "params": r.params}
@app.get("/api/risk")
def risk(u=ANY, db=Depends(get_db)):
    out = []
    for r in db.scalars(select(RiskAssessment).order_by(desc(RiskAssessment.score), desc(RiskAssessment.id)).limit(60)):
        lab = (db.get(Incident, r.incident_id).title if r.incident_id else db.get(Threat, r.threat_id).description) if (r.incident_id or r.threat_id) else ""
        out.append({"id": r.id, "kind": "incident" if r.incident_id else "threat", "label": lab, "score": r.score, "level": r.level, "factors": r.factors, "explanation": r.explanation})
    return {"config": sv.RISK, "levels": {"low": "0-29", "medium": "30-59", "high": "60-79", "critical": "80-100"}, "items": out}

# ---------- incidents ----------
@app.get("/api/incidents")
def incidents(status: str | None = None, page_: int = Query(1, alias="page"), size: int = 20, u=ANY, db=Depends(get_db)):
    qq = select(Incident).order_by(desc(Incident.risk_score), desc(Incident.created_at))
    if status: qq = qq.where(Incident.status == status)
    return page(db, qq, si, page_, size)
@app.get("/api/incidents/{iid}")
def incident(iid: str, u=ANY, db=Depends(get_db)):
    i = db.get(Incident, iid)
    if not i: raise HTTPException(404, "Incident not found")
    ts = db.scalars(select(Threat).where(Threat.incident_id == iid)).all(); rm = rmap(db, [t.id for t in ts])
    evs = db.scalars(select(Event).join(IncidentEvent, IncidentEvent.event_id == Event.id).where(IncidentEvent.incident_id == iid).order_by(Event.timestamp).limit(300))
    notes = db.scalars(select(IncidentNote).where(IncidentNote.incident_id == iid).order_by(IncidentNote.id)).all()
    names = {x.id: x.full_name for x in db.scalars(select(User))}
    ra = db.scalars(select(RiskAssessment).where(RiskAssessment.incident_id == iid).order_by(desc(RiskAssessment.id))).first()
    return {**si(i), "threats": [st(t, rm) for t in ts], "events": [se(e) for e in evs], "risk": {"factors": ra.factors, "explanation": ra.explanation} if ra else None,
            "playbooks": [{"category": k, "steps": sv.PLAYBOOKS[k]} for k in sorted({t.rule_key for t in ts}) if k in sv.PLAYBOOKS],
            "history": [{"id": n.id, "kind": n.kind, "body": n.body, "author": names.get(n.author_id, "system"), "at": n.created_at.isoformat()} for n in notes]}
class IncPatch(BaseModel): status: Literal["new", "investigating", "in_progress", "resolved", "closed"] | None = None; priority: Literal["low", "medium", "high", "critical"] | None = None; assignee_id: str | None = None
@app.patch("/api/incidents/{iid}")
def patch_inc(iid: str, b: IncPatch, req: Request, u=WRITE, db=Depends(get_db)):
    i = db.get(Incident, iid)
    if not i: raise HTTPException(404, "Incident not found")
    if b.status and b.status != i.status:
        sv._add_note(db, iid, "status", f"Status {i.status} -> {b.status}", u.id); i.status = b.status
        i.resolved_at = now() if b.status in ("resolved", "closed") and not i.resolved_at else (None if b.status not in ("resolved", "closed") else i.resolved_at)
    if b.priority and b.priority != i.priority: sv._add_note(db, iid, "priority", f"Priority {i.priority} -> {b.priority}", u.id); i.priority = b.priority
    if "assignee_id" in b.model_fields_set and b.assignee_id != i.assignee_id:
        if b.assignee_id and not db.get(User, b.assignee_id): raise HTTPException(400, "Unknown assignee")
        a = db.get(User, b.assignee_id) if b.assignee_id else None
        sv._add_note(db, iid, "assignment", f"Assigned to {a.full_name if a else 'nobody'}", u.id); i.assignee_id = b.assignee_id
    audit(db, u, "incident_update", iid, b.model_dump(exclude_unset=True), req); db.commit(); return si(i)
class Note(BaseModel): body: str = Field(min_length=1, max_length=4000); kind: Literal["note", "remediation"] = "note"
@app.post("/api/incidents/{iid}/notes", status_code=201)
def add_note(iid: str, b: Note, u=WRITE, db=Depends(get_db)):
    if not db.get(Incident, iid): raise HTTPException(404, "Incident not found")
    sv._add_note(db, iid, b.kind, b.body, u.id); db.commit(); return {"ok": True}

# ---------- AI ----------
class AIIn(BaseModel): incident_id: str | None = None; question: str | None = Field(None, max_length=1000); save_summary: bool = False
@app.post("/api/ai/analyze")
def ai_analyze(b: AIIn, req: Request, u=WRITE, db=Depends(get_db)):
    inc = db.get(Incident, b.incident_id) if b.incident_id else None
    if b.incident_id and not inc: raise HTTPException(404, "Incident not found")
    out = ai.analyze(ai.incident_context(db, inc) if inc else ai.global_context(db), b.question)
    if inc and b.save_summary: inc.summary = out["summary"]; sv._add_note(db, inc.id, "system", f"AI summary saved ({out['source']})", u.id)
    audit(db, u, "ai_analyze", b.incident_id, {"source": out["source"]}, req); db.commit(); return out

# ---------- dashboard / analytics ----------
def groups(db, col, *conds, join_event=False, n=10):
    q = select(col, func.count()).where(*conds, col.is_not(None)).group_by(col).order_by(desc(func.count())).limit(n)
    if join_event: q = q.join(Event, Event.id == Threat.event_id)
    return [{"name": str(k), "value": v} for k, v in db.execute(q)]
@app.get("/api/dashboard")
def dashboard(u=ANY, db=Depends(get_db)):
    C = lambda m, *w: db.scalar(select(func.count()).select_from(m).where(*w)) or 0
    sevc = {k: C(Threat, Threat.severity == k) for k in sv.SEV}; since = now() - dt.timedelta(days=14)
    open_ = [i.risk_score for i in db.scalars(select(Incident).where(Incident.status.in_(["new", "investigating", "in_progress"])))]
    score = round(.6 * max(open_) + .4 * sum(open_) / len(open_)) if open_ else 0
    day = func.date(Event.timestamp).label("d")
    tl = {str(d): {"day": str(d), "events": n, "threats": 0} for d, n in db.execute(select(day, func.count()).where(Event.timestamp >= since).group_by(day).order_by(day))}
    for d, n in db.execute(select(day, func.count()).select_from(Threat).join(Event, Event.id == Threat.event_id).where(Event.timestamp >= since).group_by(day)): tl.setdefault(str(d), {"day": str(d), "events": 0, "threats": 0})["threats"] = n
    rt = [{"day": str(d), "score": round(a)} for d, a in db.execute(select(day, func.avg(RiskAssessment.score)).select_from(RiskAssessment).join(Threat, Threat.id == RiskAssessment.threat_id).join(Event, Event.id == Threat.event_id).group_by(day).order_by(day))]
    ts = db.scalars(select(Threat).where(Threat.severity.in_(["high", "critical"])).order_by(desc(Threat.detected_at)).limit(6)).all(); rm = rmap(db, [t.id for t in ts])
    return {"kpis": {"total_events": C(Event), "critical_threats": sevc["critical"], "high_threats": sevc["high"], "medium_threats": sevc["medium"], "low_threats": sevc["low"],
                     "active_incidents": C(Incident, Incident.status.in_(["new", "investigating", "in_progress"])), "resolved_incidents": C(Incident, Incident.status.in_(["resolved", "closed"])), "risk_score": score, "risk_level": sv.level(score)},
            "severity": [{"name": k, "value": v} for k, v in sevc.items()], "timeline": sorted(tl.values(), key=lambda x: x["day"]), "sources": groups(db, Event.source),
            "categories": groups(db, Threat.category), "risk_trend": rt, "recent_events": [se(e) for e in db.scalars(select(Event).order_by(desc(Event.timestamp)).limit(8))],
            "critical_alerts": [st(t, rm) for t in ts]}
@app.get("/api/analytics")
def analytics(date_from: str | None = None, date_to: str | None = None, severity: str | None = None, source: str | None = None, u=ANY, db=Depends(get_db)):
    c = ev_conds(date_from, date_to, severity, source); day = func.date(Event.timestamp).label("d")
    res = [i for i in db.scalars(select(Incident).where(Incident.resolved_at.is_not(None)))]
    hrs = [(i.resolved_at - i.created_at).total_seconds() / 3600 for i in res]
    return {"daily": [{"day": str(d), "events": n} for d, n in db.execute(select(day, func.count()).where(*c).group_by(day).order_by(day))],
            "severity": groups(db, Event.severity, *c), "top_ips": groups(db, Threat.ip, *c, join_event=True), "resources": groups(db, Threat.resource, *c, join_event=True),
            "categories": groups(db, Threat.category, *c, join_event=True), "incident_status": groups(db, Incident.status),
            "resolution": {"resolved_count": len(res), "avg_hours": round(sum(hrs) / len(hrs), 2) if hrs else None}}
def safe(v):
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s   # CSV formula-injection guard
@app.get("/api/analytics/export.csv")
def export(kind: Literal["events", "threats", "incidents"] = "events", date_from: str | None = None, date_to: str | None = None, severity: str | None = None, source: str | None = None, u=ANY, db=Depends(get_db)):
    c = ev_conds(date_from, date_to, severity, source)
    if kind == "events": head = ["timestamp", "source", "event_type", "ip", "user", "resource", "action", "status", "severity"]; rows = [[e.timestamp.isoformat(), e.source, e.event_type, e.ip, e.user_identity, e.resource, e.action, e.status, e.severity] for e in db.scalars(select(Event).where(*c).order_by(Event.timestamp).limit(50000))]
    elif kind == "threats": head = ["detected_at", "category", "severity", "confidence", "user", "ip", "resource", "description"]; rows = [[t.detected_at.isoformat(), t.category, t.severity, t.confidence, t.user_identity, t.ip, t.resource, t.description] for t in db.scalars(select(Threat).join(Event, Event.id == Threat.event_id).where(*c).limit(50000))]
    else: head = ["created_at", "title", "status", "priority", "risk_score", "risk_level", "summary"]; rows = [[i.created_at.isoformat(), i.title, i.status, i.priority, i.risk_score, i.risk_level, i.summary] for i in db.scalars(select(Incident).limit(50000))]
    b = io.StringIO(); w = csv.writer(b); w.writerow(head); [w.writerow([safe(x) for x in r]) for r in rows]
    return Response(b.getvalue(), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename={kind}.csv"})

# ---------- integrations / audit ----------
@app.get("/api/integrations")
def integrations(u=ANY, db=Depends(get_db)): return [{"id": i.id, "name": i.name, "kind": i.kind, "status": i.status, "simulated": i.simulated, "description": i.description, "last_sync": i.last_sync.isoformat() if i.last_sync else None} for i in db.scalars(select(Integration))]
@app.post("/api/integrations/cloudtrail/simulate")
def sim_cloudtrail(req: Request, u=WRITE, db=Depends(get_db)):
    """SIMULATED: fabricates CloudTrail-shaped records. No AWS API is called."""
    t = now(); tag = secrets.token_hex(3); recs = []
    for i in range(6): recs.append({"eventTime": (t - dt.timedelta(seconds=40 * i)).isoformat() + "Z", "eventName": "ConsoleLogin", "sourceIPAddress": "198.51.100.77", "userIdentity": {"userName": f"sim-{tag}"}, "eventSource": "signin.amazonaws.com", "responseElements": {"ConsoleLogin": "Failure"}, "eventID": f"sim-{tag}-{i}"})
    recs.append({"eventTime": t.isoformat() + "Z", "eventName": "AttachUserPolicy", "sourceIPAddress": "198.51.100.77", "userIdentity": {"userName": f"sim-{tag}"}, "eventSource": "iam.amazonaws.com", "eventID": f"sim-{tag}-p"})
    r = sv.ingest(db, [{**x, "simulated": True} for x in recs], "cloud"); i = db.scalar(select(Integration).where(Integration.kind == "cloud")); i.last_sync = now()
    audit(db, u, "cloudtrail_simulate", None, {"accepted": r["accepted"]}, req); db.commit(); return {**r, "simulated": True}
@app.get("/api/audit")
def audit_log(u=ADMIN, db=Depends(get_db)): return [{"at": a.created_at.isoformat(), "user_id": a.user_id, "action": a.action, "target": a.target, "detail": a.detail, "ip": a.ip} for a in db.scalars(select(AuditLog).order_by(desc(AuditLog.id)).limit(100))]

# ---------- extras: MITRE, live stream, simulation, IP intel, MFA, reports, jobs ----------
@app.get("/api/mitre")
def mitre(u=ANY, db=Depends(get_db)):
    cnt = dict(db.execute(select(Threat.rule_key, func.count()).group_by(Threat.rule_key)).all())
    return [{"rule_key": r.key, "technique": sv.MITRE[r.key][0], "name": sv.MITRE[r.key][1], "tactic": sv.MITRE[r.key][2], "enabled": r.enabled, "detections": cnt.get(r.key, 0)} for r in db.scalars(select(Rule)) if r.key in sv.MITRE]
@app.get("/api/stream")
def stream(u=ANY):
    def gen():
        seen, last = set(), now() - dt.timedelta(seconds=1); yield ": connected\n\n"
        while True:
            time.sleep(2)
            with SessionLocal() as db:
                ts = [t for t in db.scalars(select(Threat).where(Threat.detected_at > last - dt.timedelta(seconds=15)).order_by(Threat.detected_at)) if t.id not in seen]
                if ts:
                    rm = rmap(db, [t.id for t in ts])
                    for t in ts: seen.add(t.id); yield f"data: {json.dumps(st(t, rm))}\n\n"
                    last = max(t.detected_at for t in ts); seen = {i for i in seen if len(seen) < 500}
                else: yield ": ping\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
def _run_sim():
    tag = secrets.token_hex(3); n = int(tag, 16); t = now(); user = f"sim-{tag}"; home = f"10.9.{n % 200}.5"; atk = f"203.0.113.{n % 200 + 20}"
    ev = lambda ts, **k: {"timestamp": ts.isoformat(), "source": k.pop("source", "authentication"), "user": user, **k}
    s1 = [ev(t - dt.timedelta(days=1, hours=i), event_type="login", ip=home, status="success", action="login") for i in range(4)] + \
         [ev(t - dt.timedelta(minutes=4) + dt.timedelta(seconds=15 * i), event_type="login", ip=atk, status="failure", action="login") for i in range(8)]
    s2 = [ev(t - dt.timedelta(minutes=1), event_type="login", ip=atk, status="success", action="login")]
    s3 = [ev(t - dt.timedelta(seconds=20), event_type="resource_access", ip=atk, status="success", action="export", resource="/payroll/export", source="application")]
    for s in (s1, s2, s3):
        with SessionLocal() as db: sv.ingest(db, s, None)
        time.sleep(3)
@app.post("/api/simulate/attack", status_code=202)
def simulate(bg: BackgroundTasks, req: Request, u=WRITE, db=Depends(get_db)):
    """Injects a SYNTHETIC attack chain in 3 stages (for demos); clearly not real traffic."""
    audit(db, u, "simulate_attack", req=req); db.commit(); bg.add_task(_run_sim); return {"started": True, "simulated": True}
DEMO_GEO = {"203.0.113.0/24": "Synthetic demo location A (doc range)", "198.51.100.0/24": "Synthetic demo location B (doc range)", "192.0.2.0/24": "Synthetic demo location C (doc range)"}
@app.get("/api/ip/{ip}")
def ip_info(ip: str, u=ANY):
    try: a = ipaddress.ip_address(ip)
    except ValueError: raise HTTPException(400, "Invalid IP address")
    out = {"ip": ip, "private": a.is_private, "geo": next((l for n, l in DEMO_GEO.items() if a in ipaddress.ip_network(n)), None), "reputation": None, "note": ""}
    key = os.getenv("ABUSEIPDB_API_KEY")
    if a.is_global and key:
        try:
            d = httpx.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip, "maxAgeInDays": 90}, headers={"Key": key, "Accept": "application/json"}, timeout=6).json()["data"]
            out["geo"] = f"{d.get('countryCode')} / {d.get('isp')}"; out["reputation"] = {"abuse_confidence": d["abuseConfidenceScore"], "reports": d["totalReports"]}; out["note"] = f"AbuseIPDB confidence {d['abuseConfidenceScore']}%"
        except Exception: out["note"] = "reputation lookup failed"
    else: out["note"] = "private/documentation range, no external lookup" if not a.is_global else "set ABUSEIPDB_API_KEY for reputation data"
    return out
class Code(BaseModel): code: str = Field(min_length=6, max_length=8)
@app.post("/api/mfa/setup")
def mfa_setup(u=ANY, db=Depends(get_db)):
    if u.mfa_enabled: raise HTTPException(400, "MFA already enabled")
    u.mfa_secret = pyotp.random_base32(); db.commit()   # NOTE: stored unencrypted; encrypt at rest in production
    return {"secret": u.mfa_secret, "uri": pyotp.TOTP(u.mfa_secret).provisioning_uri(name=u.email, issuer_name="SentinelX")}
@app.post("/api/mfa/enable")
def mfa_enable(b: Code, req: Request, u=ANY, db=Depends(get_db)):
    if not u.mfa_secret or not pyotp.TOTP(u.mfa_secret).verify(b.code, valid_window=1): raise HTTPException(400, "Invalid code")
    u.mfa_enabled = True; audit(db, u, "mfa_enable", u.id, req=req); db.commit(); return su(u)
@app.post("/api/mfa/disable")
def mfa_disable(b: Code, req: Request, u=ANY, db=Depends(get_db)):
    if not u.mfa_enabled or not pyotp.TOTP(u.mfa_secret).verify(b.code, valid_window=1): raise HTTPException(400, "Invalid code")
    u.mfa_enabled = False; u.mfa_secret = None; audit(db, u, "mfa_disable", u.id, req=req); db.commit(); return su(u)
@app.get("/api/incidents/{iid}/report")
def report(iid: str, u=ANY, db=Depends(get_db)):
    d = incident(iid, u, db); e = lambda x: html.escape(str(x if x is not None else ""))
    rows = "".join(f"<tr><td>{e(x['timestamp'])}</td><td>{e(x['event_type'])}</td><td>{e(x['user'])}</td><td>{e(x['ip'])}</td><td>{e(x['resource'])}</td><td>{e(x['status'])}</td></tr>" for x in d["events"])
    th = "".join(f"<li><b>{e(t['category'])}</b> ({e(t['severity'])}) {e(t['description'])}" + (f" &mdash; MITRE {e(t['mitre']['id'])} {e(t['mitre']['name'])}" if t["mitre"] else "") + "</li>" for t in d["threats"])
    pb = "".join(f"<li>{e(s)}</li>" for p in d["playbooks"] for s in p["steps"]); hist = "".join(f"<li>{e(h['at'])} [{e(h['kind'])}] {e(h['author'])}: {e(h['body'])}</li>" for h in d["history"])
    body = (f"<h1>Incident report: {e(d['title'])}</h1><p>Status {e(d['status'])} &middot; Priority {e(d['priority'])} &middot; Risk {d['risk_score']}/100 ({e(d['risk_level'])})</p>"
            f"<p>{e(d['risk']['explanation']) if d['risk'] else ''}</p><p>{e(d['summary'])}</p><h2>Threats</h2><ul>{th}</ul><h2>Recommended steps (manual)</h2><ul>{pb}</ul>"
            f"<h2>Events</h2><table border=1 cellpadding=4 cellspacing=0>{rows}</table><h2>Activity</h2><ul>{hist}</ul><p><i>Generated {now().isoformat()} UTC. Use the browser's Print > Save as PDF.</i></p>")
    return HTMLResponse(f"<!doctype html><meta charset=utf-8><title>Incident report</title><body style='font-family:sans-serif;max-width:900px;margin:2em auto'>{body}")
@app.get("/api/jobs/{jid}")
def job(jid: str, u=ANY):
    try:
        from redis import Redis; from rq.job import Job
        j = Job.fetch(jid, connection=Redis.from_url(os.environ["REDIS_URL"], socket_timeout=1)); return {"status": j.get_status(), "result": j.result}
    except Exception: raise HTTPException(404, "Job not found")
