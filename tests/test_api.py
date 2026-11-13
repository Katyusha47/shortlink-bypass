"""API Integration Tests for Universal Shortlink Bypasser."""

import time
import pytest
from starlette.testclient import TestClient
from app.main import app
from app.config import settings
from app.core.rate_limiter import rate_limiter
from app.core.cache import resolution_cache
from app.engine.models import ResolutionResponse, Category, Status, ResolutionMethod


@pytest.fixture
def client():
    return TestClient(app)


def test_api_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_api_providers_list(client):
    response = client.get("/api/providers")
    assert response.status_code == 200
    providers = response.json()
    assert isinstance(providers, list)
    assert len(providers) >= 10

    for p in providers:
        assert "id" in p
        assert "name" in p
        assert "category" in p
        assert "compatibility" in p
        assert "resolution_method" in p


def test_api_resolve_cached_url(client):
    test_url = "https://short.test/seeded-1"
    dest_url = "https://destination.test/welcome"

    # Pre-seed cache
    resolution_cache.set(
        test_url,
        ResolutionResponse(
            success=True,
            original_url=test_url,
            destination_url=dest_url,
            provider="Seed Provider",
            category=Category.TRADITIONAL,
            resolution_method=ResolutionMethod.HTTP_REDIRECT,
            redirect_count=1,
            status=Status.RESOLVED,
        ),
    )

    response = client.post("/api/resolve", json={"url": test_url})
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["destination_url"] == dest_url
    assert data["status"] == "resolved"


def test_api_resolve_invalid_url(client):
    response = client.post("/api/resolve", json={"url": "javascript:alert(1)"})
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is False
    assert data["status"] in ("invalid_url", "blocked")


def test_api_resolve_ssrf_attempt(client):
    response = client.post("/api/resolve", json={"url": "http://127.0.0.1:8080/admin"})
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is False
    assert data["status"] == "blocked"
    assert "restricted" in data["error"].lower() or "blocked" in data["error"].lower()


def test_api_rate_limiting(client):
    rate_limiter.hits.clear()
    client_ip = "192.0.2.1"
    now = time.time()

    # Exhaust rate limit by populating hits with current timestamp
    limit = settings.RATE_LIMIT_REQUESTS_PER_MINUTE
    rate_limiter.hits[client_ip] = [now] * limit

    # Now make request with X-Forwarded-For: client_ip
    response = client.post(
        "/api/resolve",
        json={"url": "https://example.com/test"},
        headers={"X-Forwarded-For": client_ip},
    )
    assert response.status_code == 429
    assert "Retry-After" in response.headers
    data = response.json()
    assert "Rate limit exceeded" in str(data)

    rate_limiter.hits.clear()
