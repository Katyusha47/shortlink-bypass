"""Provider-independent resolution pipeline.

Orchestrates URL normalization, validation, provider identification,
strategy execution, redirect-chain verification, and response generation.
"""

from __future__ import annotations
from typing import Optional
from urllib.parse import urlsplit

from app.engine.models import (
    ResolutionResponse,
    Status,
    Category,
    ResolutionMethod,
)
from app.engine.registry import registry
from app.core.security import (
    validate_and_normalize_url,
    verify_target_safety,
    SSRFSecurityError,
    InvalidURLError,
)
from app.core.http_client import SafeHttpClient
from app.core.cache import resolution_cache
from app.config import settings


class ResolutionPipeline:
    """End-to-end shortlink resolution pipeline."""

    def __init__(self, client: Optional[SafeHttpClient] = None):
        self.client = client or SafeHttpClient()

    async def execute(self, raw_url: str) -> ResolutionResponse:
        # Step 1: URL Normalization & Syntax Validation
        try:
            normalized_url = validate_and_normalize_url(raw_url)
        except InvalidURLError as exc:
            return ResolutionResponse(
                success=False,
                original_url=raw_url,
                provider="Unknown",
                category=Category.GENERIC_REDIRECT,
                resolution_method=ResolutionMethod.HTTP_REDIRECT,
                status=Status.INVALID_URL,
                error=str(exc),
            )
        except SSRFSecurityError as exc:
            return ResolutionResponse(
                success=False,
                original_url=raw_url,
                provider="Unknown",
                category=Category.GENERIC_REDIRECT,
                resolution_method=ResolutionMethod.HTTP_REDIRECT,
                status=Status.BLOCKED,
                error=f"Blocked: {exc}",
            )

        # Step 2: Cache Check
        cached_result = resolution_cache.get(normalized_url)
        if cached_result:
            return cached_result

        # Step 3: Provider Identification
        provider = registry.find_provider_for_url(normalized_url)

        # Step 4: Initial Pre-flight Safety Verification
        try:
            verify_target_safety(normalized_url)
        except SSRFSecurityError as exc:
            return ResolutionResponse(
                success=False,
                original_url=normalized_url,
                provider=provider.name,
                category=provider.category,
                resolution_method=provider.resolution_method,
                status=Status.BLOCKED,
                error=f"Security restriction: {exc}",
            )
        except InvalidURLError as exc:
            return ResolutionResponse(
                success=False,
                original_url=normalized_url,
                provider=provider.name,
                category=provider.category,
                resolution_method=provider.resolution_method,
                status=Status.INVALID_URL,
                error=str(exc),
            )

        # Step 5: Provider-Specific Execution
        try:
            result = await provider.resolve(normalized_url, self.client)
        except TimeoutError as exc:
            return ResolutionResponse(
                success=False,
                original_url=normalized_url,
                provider=provider.name,
                category=provider.category,
                resolution_method=provider.resolution_method,
                status=Status.TIMEOUT,
                error=f"Resolution timed out: {exc}",
            )
        except Exception as exc:
            return ResolutionResponse(
                success=False,
                original_url=normalized_url,
                provider=provider.name,
                category=provider.category,
                resolution_method=provider.resolution_method,
                status=Status.PROVIDER_ERROR,
                error=f"Provider resolution failed: {exc}",
            )

        # Step 6 & 7: Destination Verification & SSRF Check on Destination
        if result.success and result.destination_url:
            try:
                dest_norm = validate_and_normalize_url(result.destination_url)
                # Verify destination is not an internal / private IP
                verify_target_safety(dest_norm)
                result.destination_url = dest_norm
            except SSRFSecurityError as exc:
                return ResolutionResponse(
                    success=False,
                    original_url=normalized_url,
                    destination_url=None,
                    provider=provider.name,
                    category=provider.category,
                    resolution_method=provider.resolution_method,
                    status=Status.BLOCKED,
                    error=f"Destination redirected to restricted address: {exc}",
                )
            except InvalidURLError:
                # If destination cannot be parsed as valid HTTP/HTTPS URL
                pass

        # Step 8: Cache Safe Success Results
        if result.success and result.destination_url:
            resolution_cache.set(normalized_url, result, ttl=settings.CACHE_TTL_SECONDS)

        return result


pipeline = ResolutionPipeline()

