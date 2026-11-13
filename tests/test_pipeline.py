"""Tests for Resolution Pipeline."""

import asyncio
from app.engine.pipeline import ResolutionPipeline
from app.engine.models import Status, Category, ResolutionResponse, ResolutionMethod
from app.core.cache import resolution_cache


def test_pipeline_invalid_url():
    pipeline = ResolutionPipeline()
    res = asyncio.run(pipeline.execute("javascript:alert(1)"))
    assert res.success is False
    assert res.status == Status.INVALID_URL
    assert "Unsupported protocol" in (res.error or "")


def test_pipeline_blocked_ssrf():
    pipeline = ResolutionPipeline()
    res = asyncio.run(pipeline.execute("http://127.0.0.1:8080/admin"))
    assert res.success is False
    assert res.status == Status.BLOCKED
    assert "restricted" in (res.error or "").lower() or "blocked" in (res.error or "").lower()


def test_pipeline_cache_mechanism():
    pipeline = ResolutionPipeline()
    url = "https://example-test-cache.org/short1"

    cached_response = ResolutionResponse(
        success=True,
        original_url=url,
        destination_url="https://destination.example.org/target",
        provider="Generic Redirect Resolver",
        category=Category.GENERIC_REDIRECT,
        resolution_method=ResolutionMethod.HTTP_REDIRECT,
        redirect_count=1,
        status=Status.RESOLVED,
    )
    resolution_cache.set(url, cached_response, ttl=60)

    result = asyncio.run(pipeline.execute(url))
    assert result.success is True
    assert result.destination_url == "https://destination.example.org/target"
    assert result.status == Status.RESOLVED


def test_pipeline_prevents_destination_ssrf(monkeypatch):
    """If a shortlink tries to redirect to 127.0.0.1 or cloud metadata, destination check must catch it."""
    from app.engine.base import BaseProvider
    from app.core.http_client import SafeHttpClient

    class MaliciousRedirectProvider(BaseProvider):
        id = "malicious"
        name = "Malicious"

        async def resolve(self, url: str, client: SafeHttpClient):
            return ResolutionResponse(
                success=True,
                original_url=url,
                destination_url="http://169.254.169.254/latest/meta-data",
                provider=self.name,
                category=Category.GENERIC_REDIRECT,
                resolution_method=ResolutionMethod.HTTP_REDIRECT,
                status=Status.RESOLVED,
            )

    from app.engine.registry import registry
    mal_provider = MaliciousRedirectProvider()
    monkeypatch.setattr(registry, "find_provider_for_url", lambda u: mal_provider)

    import app.engine.pipeline as pipe_mod
    monkeypatch.setattr(pipe_mod, "verify_target_safety", lambda u: (u, "example.com", ["93.184.216.34"]))

    pipeline = ResolutionPipeline()
    result = asyncio.run(pipeline.execute("https://example.com/redirect-to-metadata"))

    assert result.success is False
    assert result.status == Status.BLOCKED
    assert "restricted address" in (result.error or "").lower()
