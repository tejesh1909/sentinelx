import os, secrets, time, datetime as dt
from collections import defaultdict
import jwt
from argon2 import PasswordHasher
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

ENV = os.getenv("APP_ENV", "development")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sentinelx.db")
JWT_SECRET = os.getenv("JWT_SECRET") or secrets.token_urlsafe(48)
if ENV == "production" and not os.getenv("JWT_SECRET"):
    raise RuntimeError("JWT_SECRET must be set in production")
engine = create_engine(DATABASE_URL, pool_pre_ping=True,
                       connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(engine, autoflush=False)

class Base(DeclarativeBase): pass

def now():  # naive UTC everywhere
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)

_ph = PasswordHasher()
def hash_pw(p): return _ph.hash(p)
def verify_pw(h, p):
    try: return _ph.verify(h, p)
    except Exception: return False

def make_token(sub, kind, minutes, jti=None):
    exp = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=minutes)
    return jwt.encode({"sub": sub, "type": kind, "exp": exp, "jti": jti or secrets.token_hex(8)}, JWT_SECRET, "HS256")
def decode(t): return jwt.decode(t, JWT_SECRET, algorithms=["HS256"])

_mem = defaultdict(list); _r = None
def hit(key, limit, win=60):
    """Sliding-window rate limit; Redis if reachable, in-memory fallback."""
    global _r
    url = os.getenv("REDIS_URL")
    if url:
        try:
            import redis
            _r = _r or redis.Redis.from_url(url, socket_timeout=0.3)
            k = f"rl:{key}"; n = _r.incr(k)
            if n == 1: _r.expire(k, win)
            return n <= limit
        except Exception: pass
    t = time.time(); q = [x for x in _mem[key] if x > t - win] + [t]; _mem[key] = q
    return len(q) <= limit
