import os, tempfile
os.environ.update(DATABASE_URL=f"sqlite:///{tempfile.mkdtemp()}/t.db", RATE_LIMIT_DISABLED="1", JWT_SECRET="x" * 40, DEMO_ADMIN_PASSWORD="TestPass!12345")
import pytest
from fastapi.testclient import TestClient
from app.core import Base, engine, SessionLocal
from app import models  # noqa
from app.seed import seed_base
from app.main import app
Base.metadata.create_all(engine)
with SessionLocal() as _db: seed_base(_db)
@pytest.fixture(scope="session")
def client(): return TestClient(app)
@pytest.fixture(scope="session")
def admin(client):
    r = client.post("/api/auth/login", json={"email": "admin@sentinelx.local", "password": "TestPass!12345"}); assert r.status_code == 200
    return {"Authorization": "Bearer " + r.json()["access_token"]}
