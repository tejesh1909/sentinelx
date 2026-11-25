"""Idempotent seeding: roles/rules/admin/integrations always; sample events only if the events table is empty."""
import os, random, datetime as dt
from sqlalchemy import select, func
from .core import SessionLocal, Base, engine, ENV, hash_pw, now
from .models import *
from .services import DEFAULT_RULES, ingest

def sample_events(base):
    R = random.Random(7); ev = []; users = ["alice", "bob", "carol", "dave", "erin", "frank"]
    ip = {u: f"10.0.{i}.{10 + i}" for i, u in enumerate(users)}; t0 = base - dt.timedelta(days=5)
    E = lambda ts, **k: ev.append({"timestamp": ts.isoformat(), "source": k.pop("source", "application"), **k})
    for i in range(55):
        u = R.choice(users); E(t0 + dt.timedelta(minutes=R.randint(0, 5 * 1440), seconds=i), event_type="login", user=u, ip=ip[u], status="success", resource="/login", action="login", source="authentication")
    for i in range(5): E(t0 + dt.timedelta(hours=i * 7, seconds=99), event_type="login", user="carol", ip=ip["carol"], status="success", action="login", resource="/login", source="authentication")
    for i in range(25):
        u = R.choice(users); E(t0 + dt.timedelta(minutes=R.randint(0, 5 * 1440), seconds=i), event_type="api_request", user=u, ip=ip[u], status="200", resource=f"/api/v1/orders/{i}", action="get", source="api_gateway")
    a = base - dt.timedelta(hours=2)   # scenario A: failed logins -> success from new IP -> sensitive access
    for i in range(12): E(a + dt.timedelta(seconds=20 * i), event_type="login", user="carol", ip="203.0.113.50", status="failure", action="login", resource="/login", source="authentication")
    E(a + dt.timedelta(minutes=5), event_type="login", user="carol", ip="203.0.113.50", status="success", action="login", resource="/login", source="authentication")
    E(a + dt.timedelta(minutes=8), event_type="resource_access", user="carol", ip="203.0.113.50", status="success", action="export", resource="/payroll/export", source="application")
    b = base - dt.timedelta(hours=9)   # scenario B: API probing
    for i in range(8): E(b + dt.timedelta(seconds=30 * i), event_type="api_request", ip="198.51.100.23", status="403", action="get", resource=f"/api/v1/admin/{['users','keys','config','backup','logs','roles','tokens','db'][i]}", source="api_gateway")
    c = (base - dt.timedelta(days=1)).replace(hour=3, minute=10)   # scenario C: privilege escalation + off-hours admin
    E(c, event_type="admin_action", user="admin", ip="10.0.9.9", status="success", action="delete_user", resource="/admin/users/42", source="application")
    E(c + dt.timedelta(minutes=30), event_type="role_change", user="dave", ip=ip["dave"], status="success", action="grant_role", resource="/iam/roles/admin", source="application")
    d = base - dt.timedelta(hours=5)   # scenario D: request flood
    for i in range(60): E(d + dt.timedelta(seconds=i * .9), event_type="api_request", ip="192.0.2.77", status="200", action="get", resource=f"/api/v1/items/{i}", source="api_gateway")
    return ev

def seed_base(db):
    for n in ("admin", "analyst"):
        if not db.scalar(select(Role).where(Role.name == n)): db.add(Role(name=n))
    db.flush()
    for k, n, d, p in DEFAULT_RULES:
        if not db.scalar(select(Rule).where(Rule.key == k)): db.add(Rule(key=k, name=n, description=d, params=p))
    pw = os.getenv("DEMO_ADMIN_PASSWORD")
    if ENV == "production" and (not pw or pw == "ChangeMe!Dev2026"): raise RuntimeError("Set a strong DEMO_ADMIN_PASSWORD (or remove demo seeding) in production")
    email = os.getenv("DEMO_ADMIN_EMAIL", "admin@sentinelx.local")
    if not db.scalar(select(User).where(User.email == email)):
        r = db.scalar(select(Role).where(Role.name == "admin"))
        db.add(User(email=email, full_name="Demo Admin", password_hash=hash_pw(pw or "ChangeMe!Dev2026"), role_id=r.id, must_change_password=True))
    if not db.scalar(select(func.count()).select_from(Integration)):
        db.add_all([Integration(name="REST / file ingestion", kind="rest", status="active", simulated=False, description="POST /api/events/ingest, JSON/CSV upload."),
                    Integration(name="AWS CloudTrail", kind="cloud", status="simulated", simulated=True, description="SIMULATED. Generates CloudTrail-shaped records; no AWS connection exists. Real path: CloudTrail -> S3 -> SQS -> worker calling services.ingest().")])
    db.commit()

def seed(db):
    seed_base(db)
    if not db.scalar(select(func.count()).select_from(Event)): ingest(db, sample_events(now()), None)

if __name__ == "__main__":
    import sys, json
    if "dump" in sys.argv: print(json.dumps(sample_events(now()), indent=1)); sys.exit()
    if ENV != "production": Base.metadata.create_all(engine)
    with SessionLocal() as db: seed(db)
    print("seed complete")
