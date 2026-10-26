"""
Pytest Test Configuration & Client Fixtures
"""
import sys
import os

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.main import app
from app.core.database import Base, get_db
from app.core.config import settings
from app.db.seed import seed_database

# Use in-memory SQLite with StaticPool so all connections share the same memory tables
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="function")
def db_session():
    """Create fresh database tables for each test and seed initial data."""
    Base.metadata.create_all(bind=test_engine)
    db = TestingSessionLocal()
    seed_database(db)
    yield db
    db.close()
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def client(db_session):
    """FastAPI TestClient with overridden get_db dependency."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def auth_headers_analyst(client):
    """Obtain JWT Bearer auth headers for Lead Analyst (Sarah Chen)."""
    res = client.post("/api/auth/login", json={
        "email": "sarah.chen@cybersentinel.ai",
        "password": "Password123!",
    })
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def auth_headers_admin(client):
    """Obtain JWT Bearer auth headers for Security Admin."""
    res = client.post("/api/auth/login", json={
        "email": "admin@cybersentinel.ai",
        "password": "Password123!",
    })
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def auth_headers_viewer(client):
    """Obtain JWT Bearer auth headers for Viewer (Yuki Tanaka)."""
    res = client.post("/api/auth/login", json={
        "email": "viewer@cybersentinel.ai",
        "password": "Password123!",
    })
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
