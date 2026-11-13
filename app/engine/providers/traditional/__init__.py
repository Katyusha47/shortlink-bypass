"""Category A: Traditional URL Shorteners (Bitly, TinyURL, is.gd, t.co, etc.)"""

from __future__ import annotations
import json
from urllib.parse import urlsplit, urlunsplit, quote
import httpx

from app.engine.base import BaseProvider
from app.engine.models import (
    Category,
    Status,
    CompatibilityState,
    ResolutionMethod,
    ResolutionResponse,
)
from app.core.http_client import SafeHttpClient
from app.core.security import SSRFSecurityError, InvalidURLError


class BitlyProvider(BaseProvider):
    """Bitly shortlink resolver with redirect tracking and preview support."""

    id: str = "bitly"
    name: str = "Bitly"
    category: Category = Category.TRADITIONAL
    compatibility: CompatibilityState = CompatibilityState.SUPPORTED
    domains: list[str] = ["bit.ly", "bitly.com", "j.mp", "bitly.is"]
    description: str = "Resolves bit.ly, bitly.com, and j.mp shortlinks."
    resolution_method: ResolutionMethod = ResolutionMethod.HTTP_REDIRECT

    async def resolve(self, url: str, client: SafeHttpClient) -> ResolutionResponse:
        try:
            final_url, trace, html_content, last_resp = await client.follow_redirect_chain(
                start_url=url,
                timeout=self.timeout,
            )

            # Check if Bitly displayed a warning page (e.g. flagged link)
            if html_content and "Warning: This link might be unsafe" in html_content:
                # Attempt to extract the original destination from the warning page
                soup_dest = self.extract_canonical_or_og_url(html_content)
                if soup_dest:
                    final_url = soup_dest

            hop_dicts = [h.to_dict() for h in trace]
            status_code = last_resp.status_code if last_resp else 200

            if status_code in (404, 410):
                return ResolutionResponse(
                    success=False,
                    original_url=url,
                    provider=self.name,
                    category=self.category,
                    resolution_method=self.resolution_method,
                    redirect_count=max(0, len(trace) - 1),
                    status=Status.EXPIRED,
                    error="This Bitly link has expired or was removed.",
                    trace=hop_dicts,
                )

            return ResolutionResponse(
                success=True,
                original_url=url,
                destination_url=final_url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                redirect_count=max(0, len(trace) - 1),
                status=Status.RESOLVED,
                trace=hop_dicts,
            )
        except Exception as exc:
            return ResolutionResponse(
                success=False,
                original_url=url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                status=Status.PROVIDER_ERROR,
                error=str(exc),
            )


class TinyUrlProvider(BaseProvider):
    """TinyURL shortlink resolver."""

    id: str = "tinyurl"
    name: str = "TinyURL"
    category: Category = Category.TRADITIONAL
    compatibility: CompatibilityState = CompatibilityState.SUPPORTED
    domains: list[str] = ["tinyurl.com"]
    description: str = "Resolves TinyURL shortened links."
    resolution_method: ResolutionMethod = ResolutionMethod.HTTP_REDIRECT

    async def resolve(self, url: str, client: SafeHttpClient) -> ResolutionResponse:
        try:
            final_url, trace, _, last_resp = await client.follow_redirect_chain(
                start_url=url,
                timeout=self.timeout,
            )
            hop_dicts = [h.to_dict() for h in trace]
            status_code = last_resp.status_code if last_resp else 200

            if status_code in (404, 410):
                return ResolutionResponse(
                    success=False,
                    original_url=url,
                    provider=self.name,
                    category=self.category,
                    resolution_method=self.resolution_method,
                    status=Status.EXPIRED,
                    error="TinyURL not found or expired.",
                    trace=hop_dicts,
                )

            return ResolutionResponse(
                success=True,
                original_url=url,
                destination_url=final_url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                redirect_count=max(0, len(trace) - 1),
                status=Status.RESOLVED,
                trace=hop_dicts,
            )
        except Exception as exc:
            return ResolutionResponse(
                success=False,
                original_url=url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                status=Status.PROVIDER_ERROR,
                error=str(exc),
            )


class IsGdProvider(BaseProvider):
    """is.gd & v.gd resolver utilizing official public JSON lookup API with fallback."""

    id: str = "isgd"
    name: str = "is.gd / v.gd"
    category: Category = Category.TRADITIONAL
    compatibility: CompatibilityState = CompatibilityState.SUPPORTED
    domains: list[str] = ["is.gd", "v.gd"]
    description: str = "Resolves is.gd and v.gd shortlinks using official lookup API and redirect tracing."
    resolution_method: ResolutionMethod = ResolutionMethod.API_LOOKUP

    async def resolve(self, url: str, client: SafeHttpClient) -> ResolutionResponse:
        parsed = urlsplit(url)
        domain = parsed.hostname.lower() if parsed.hostname else "is.gd"
        lookup_api = f"https://{domain}/forward.php?format=json&shorturl={quote(url)}"

        try:
            # Query official public API first
            resp, text = await client.fetch_head_or_get(lookup_api, timeout=self.timeout)
            if resp.status_code == 200 and text:
                data = json.loads(text)
                if "url" in data:
                    return ResolutionResponse(
                        success=True,
                        original_url=url,
                        destination_url=data["url"],
                        provider=self.name,
                        category=self.category,
                        resolution_method=ResolutionMethod.API_LOOKUP,
                        redirect_count=1,
                        status=Status.RESOLVED,
                    )
                elif "errormessage" in data:
                    return ResolutionResponse(
                        success=False,
                        original_url=url,
                        provider=self.name,
                        category=self.category,
                        resolution_method=ResolutionMethod.API_LOOKUP,
                        status=Status.EXPIRED if "not found" in data["errormessage"].lower() else Status.INACCESSIBLE,
                        error=data["errormessage"],
                    )
        except Exception:
            pass  # Fall back to standard redirect following

        # Fallback to redirect chain
        try:
            final_url, trace, _, last_resp = await client.follow_redirect_chain(url, timeout=self.timeout)
            return ResolutionResponse(
                success=True,
                original_url=url,
                destination_url=final_url,
                provider=self.name,
                category=self.category,
                resolution_method=ResolutionMethod.HTTP_REDIRECT,
                redirect_count=max(0, len(trace) - 1),
                status=Status.RESOLVED,
                trace=[h.to_dict() for h in trace],
            )
        except Exception as exc:
            return ResolutionResponse(
                success=False,
                original_url=url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                status=Status.PROVIDER_ERROR,
                error=str(exc),
            )


class TcoProvider(BaseProvider):
    """Twitter / X (t.co) URL resolver handling HTML meta refresh and redirect tags."""

    id: str = "tco"
    name: str = "Twitter / X (t.co)"
    category: Category = Category.TRADITIONAL
    compatibility: CompatibilityState = CompatibilityState.SUPPORTED
    domains: list[str] = ["t.co"]
    description: str = "Resolves Twitter / X t.co shortlinks via HTTP headers and HTML meta-refresh."
    resolution_method: ResolutionMethod = ResolutionMethod.HTML_META_REFRESH

    async def resolve(self, url: str, client: SafeHttpClient) -> ResolutionResponse:
        try:
            final_url, trace, html_content, last_resp = await client.follow_redirect_chain(
                start_url=url,
                timeout=self.timeout,
            )

            # t.co often wraps destination in <META http-equiv="refresh" content="0;URL=...">
            destination = final_url
            if html_content:
                meta_url = self.extract_meta_refresh(html_content)
                if meta_url:
                    destination = meta_url

            return ResolutionResponse(
                success=True,
                original_url=url,
                destination_url=destination,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                redirect_count=max(0, len(trace) - 1),
                status=Status.RESOLVED,
                trace=[h.to_dict() for h in trace],
            )
        except Exception as exc:
            return ResolutionResponse(
                success=False,
                original_url=url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                status=Status.PROVIDER_ERROR,
                error=str(exc),
            )


class ShortUrlAtProvider(BaseProvider):
    """shorturl.at resolver."""

    id: str = "shorturl_at"
    name: str = "ShortURL.at"
    category: Category = Category.TRADITIONAL
    compatibility: CompatibilityState = CompatibilityState.SUPPORTED
    domains: list[str] = ["shorturl.at"]
    description: str = "Resolves shorturl.at shortened URLs."
    resolution_method: ResolutionMethod = ResolutionMethod.HTTP_REDIRECT

    async def resolve(self, url: str, client: SafeHttpClient) -> ResolutionResponse:
        try:
            final_url, trace, _, last_resp = await client.follow_redirect_chain(url, timeout=self.timeout)
            return ResolutionResponse(
                success=True,
                original_url=url,
                destination_url=final_url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                redirect_count=max(0, len(trace) - 1),
                status=Status.RESOLVED,
                trace=[h.to_dict() for h in trace],
            )
        except Exception as exc:
            return ResolutionResponse(
                success=False,
                original_url=url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                status=Status.PROVIDER_ERROR,
                error=str(exc),
            )


class RebrandlyProvider(BaseProvider):
    """Rebrandly & rb.gy resolver."""

    id: str = "rebrandly"
    name: str = "Rebrandly / rb.gy"
    category: Category = Category.TRADITIONAL
    compatibility: CompatibilityState = CompatibilityState.SUPPORTED
    domains: list[str] = ["rebrand.ly", "rb.gy"]
    description: str = "Resolves Rebrandly and rb.gy branded short links."
    resolution_method: ResolutionMethod = ResolutionMethod.HTTP_REDIRECT

    async def resolve(self, url: str, client: SafeHttpClient) -> ResolutionResponse:
        try:
            final_url, trace, _, last_resp = await client.follow_redirect_chain(url, timeout=self.timeout)
            return ResolutionResponse(
                success=True,
                original_url=url,
                destination_url=final_url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                redirect_count=max(0, len(trace) - 1),
                status=Status.RESOLVED,
                trace=[h.to_dict() for h in trace],
            )
        except Exception as exc:
            return ResolutionResponse(
                success=False,
                original_url=url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                status=Status.PROVIDER_ERROR,
                error=str(exc),
            )


class CuttlyProvider(BaseProvider):
    """Cutt.ly resolver."""

    id: str = "cuttly"
    name: str = "Cutt.ly"
    category: Category = Category.TRADITIONAL
    compatibility: CompatibilityState = CompatibilityState.SUPPORTED
    domains: list[str] = ["cutt.ly"]
    description: str = "Resolves cutt.ly shortlinks."
    resolution_method: ResolutionMethod = ResolutionMethod.HTTP_REDIRECT

    async def resolve(self, url: str, client: SafeHttpClient) -> ResolutionResponse:
        try:
            final_url, trace, html, last_resp = await client.follow_redirect_chain(url, timeout=self.timeout)
            if html:
                meta = self.extract_meta_refresh(html)
                if meta:
                    final_url = meta
            return ResolutionResponse(
                success=True,
                original_url=url,
                destination_url=final_url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                redirect_count=max(0, len(trace) - 1),
                status=Status.RESOLVED,
                trace=[h.to_dict() for h in trace],
            )
        except Exception as exc:
            return ResolutionResponse(
                success=False,
                original_url=url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                status=Status.PROVIDER_ERROR,
                error=str(exc),
            )

