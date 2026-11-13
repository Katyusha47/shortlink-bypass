"""Category B: Advertising-Based Shortlinks & Intermediary Gates."""

from __future__ import annotations
import base64
import json
import re
from urllib.parse import urlsplit, parse_qs, unquote, urljoin
from bs4 import BeautifulSoup

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


def decode_embedded_url(candidate: str) -> str | None:
    """Helper to detect and decode URL or base64-encoded URL."""
    if not candidate:
        return None
    candidate = unquote(candidate.strip())

    if candidate.startswith("http://") or candidate.startswith("https://"):
        return candidate

    # Try base64 decode
    try:
        # Pad if necessary
        padded = candidate + "=" * (-len(candidate) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore").strip()
        if decoded.startswith("http://") or decoded.startswith("https://"):
            return decoded
    except Exception:
        pass

    return None


class LinkvertiseProvider(BaseProvider):
    """Linkvertise provider adapter.
    
    Inspects public parameters and metadata without bypassing CAPTCHAs
    or access-control protections.
    """

    id: str = "linkvertise"
    name: str = "Linkvertise"
    category: Category = Category.ADVERTISING
    compatibility: CompatibilityState = CompatibilityState.PARTIAL
    domains: list[str] = [
        "linkvertise.com",
        "linkvertise.net",
        "link-to.net",
        "up-to-down.net",
        "direct-link.net",
        "file-link.net",
    ]
    description: str = (
        "Inspects publicly accessible parameters and metadata on Linkvertise links. "
        "Strictly respects access controls and human verification gates."
    )
    resolution_method: ResolutionMethod = ResolutionMethod.PROVIDER_ADAPTER

    async def resolve(self, url: str, client: SafeHttpClient) -> ResolutionResponse:
        parsed = urlsplit(url)
        query = parse_qs(parsed.query)

        # 1. Check for query parameter destination (e.g. r=, dest=, url=)
        for param in ("r", "dest", "target", "url", "redirect"):
            if param in query:
                val = query[param][0]
                decoded = decode_embedded_url(val)
                if decoded:
                    return ResolutionResponse(
                        success=True,
                        original_url=url,
                        destination_url=decoded,
                        provider=self.name,
                        category=self.category,
                        resolution_method=ResolutionMethod.PROVIDER_ADAPTER,
                        redirect_count=1,
                        status=Status.RESOLVED,
                    )

        # 2. Fetch intermediate page safely to inspect public meta tags
        try:
            resp, html = await client.fetch_head_or_get(url, timeout=self.timeout)

            # Check for Cloudflare Turnstile / anti-bot / access control gate
            if "cf-turnstile" in html or "challenge-platform" in html or resp.status_code == 403:
                return ResolutionResponse(
                    success=False,
                    original_url=url,
                    provider=self.name,
                    category=self.category,
                    resolution_method=self.resolution_method,
                    status=Status.BLOCKED,
                    error=(
                        "Linkvertise destination is protected by an interactive security challenge or "
                        "access control. Automated bypass of human verification is prohibited by security policy."
                    ),
                )

            # Check for canonical or target link in HTML
            canonical = self.extract_canonical_or_og_url(html)
            if canonical and not any(d in canonical for d in self.domains):
                return ResolutionResponse(
                    success=True,
                    original_url=url,
                    destination_url=canonical,
                    provider=self.name,
                    category=self.category,
                    resolution_method=ResolutionMethod.INTERMEDIATE_PAGE,
                    redirect_count=1,
                    status=Status.RESOLVED,
                )

            return ResolutionResponse(
                success=False,
                original_url=url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                status=Status.UNSUPPORTED,
                error=(
                    "Target link requires interactive user progression or authentication that "
                    "cannot be resolved via public static inspection."
                ),
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


class LootLabsProvider(BaseProvider):
    """LootLabs provider adapter."""

    id: str = "lootlabs"
    name: str = "LootLabs"
    category: Category = Category.ADVERTISING
    compatibility: CompatibilityState = CompatibilityState.PARTIAL
    domains: list[str] = ["lootlabs.gg", "loot-link.com", "loot-links.com", "lootdest.com"]
    description: str = "Resolves LootLabs links with public redirect parameters and static destinations."
    resolution_method: ResolutionMethod = ResolutionMethod.PROVIDER_ADAPTER

    async def resolve(self, url: str, client: SafeHttpClient) -> ResolutionResponse:
        parsed = urlsplit(url)
        query = parse_qs(parsed.query)

        for param in ("r", "url", "destination", "dest"):
            if param in query:
                decoded = decode_embedded_url(query[param][0])
                if decoded:
                    return ResolutionResponse(
                        success=True,
                        original_url=url,
                        destination_url=decoded,
                        provider=self.name,
                        category=self.category,
                        resolution_method=ResolutionMethod.PROVIDER_ADAPTER,
                        redirect_count=1,
                        status=Status.RESOLVED,
                    )

        try:
            resp, html = await client.fetch_head_or_get(url, timeout=self.timeout)
            if "cf-turnstile" in html or "challenge" in html:
                return ResolutionResponse(
                    success=False,
                    original_url=url,
                    provider=self.name,
                    category=self.category,
                    resolution_method=self.resolution_method,
                    status=Status.BLOCKED,
                    error="Link is protected by an interactive security challenge.",
                )

            canonical = self.extract_canonical_or_og_url(html)
            if canonical and not any(d in canonical for d in self.domains):
                return ResolutionResponse(
                    success=True,
                    original_url=url,
                    destination_url=canonical,
                    provider=self.name,
                    category=self.category,
                    resolution_method=ResolutionMethod.INTERMEDIATE_PAGE,
                    redirect_count=1,
                    status=Status.RESOLVED,
                )

            return ResolutionResponse(
                success=False,
                original_url=url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                status=Status.UNSUPPORTED,
                error="Interactive ad-wall requires human participation; automated resolution not possible.",
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


class OuoIoProvider(BaseProvider):
    """ouo.io / ouo.press intermediate provider adapter."""

    id: str = "ouo_io"
    name: str = "ouo.io / ouo.press"
    category: Category = Category.ADVERTISING
    compatibility: CompatibilityState = CompatibilityState.PARTIAL
    domains: list[str] = ["ouo.io", "ouo.press"]
    description: str = "Inspects intermediate landing pages for ouo.io and ouo.press links."
    resolution_method: ResolutionMethod = ResolutionMethod.INTERMEDIATE_PAGE

    async def resolve(self, url: str, client: SafeHttpClient) -> ResolutionResponse:
        try:
            resp, html = await client.fetch_head_or_get(url, timeout=self.timeout)

            # Check if CAPTCHA or protection is active
            if "g-recaptcha" in html or "h-captcha" in html or "cf-turnstile" in html:
                return ResolutionResponse(
                    success=False,
                    original_url=url,
                    provider=self.name,
                    category=self.category,
                    resolution_method=self.resolution_method,
                    status=Status.BLOCKED,
                    error=(
                        "Link is protected by a CAPTCHA verification gate. "
                        "Circumventing CAPTCHA protections is not supported."
                    ),
                )

            # Check for direct form action or destination anchor
            soup = BeautifulSoup(html, "html.parser")
            form = soup.find("form")
            if form and form.get("action"):
                action = form["action"]
                if action.startswith("http://") or action.startswith("https://"):
                    if not any(d in action for d in self.domains):
                        return ResolutionResponse(
                            success=True,
                            original_url=url,
                            destination_url=action,
                            provider=self.name,
                            category=self.category,
                            resolution_method=ResolutionMethod.INTERMEDIATE_PAGE,
                            redirect_count=1,
                            status=Status.RESOLVED,
                        )

            return ResolutionResponse(
                success=False,
                original_url=url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                status=Status.UNSUPPORTED,
                error="Intermediate link requires interactive navigation.",
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


class ExeIoProvider(BaseProvider):
    """exe.io / exey.io provider adapter."""

    id: str = "exe_io"
    name: str = "exe.io"
    category: Category = Category.ADVERTISING
    compatibility: CompatibilityState = CompatibilityState.PARTIAL
    domains: list[str] = ["exe.io", "exey.io"]
    description: str = "Resolves exe.io advertising shortlinks via parameter and metadata decoding."
    resolution_method: ResolutionMethod = ResolutionMethod.PROVIDER_ADAPTER

    async def resolve(self, url: str, client: SafeHttpClient) -> ResolutionResponse:
        parsed = urlsplit(url)
        query = parse_qs(parsed.query)

        for param in ("url", "dest", "safeurl", "r"):
            if param in query:
                decoded = decode_embedded_url(query[param][0])
                if decoded:
                    return ResolutionResponse(
                        success=True,
                        original_url=url,
                        destination_url=decoded,
                        provider=self.name,
                        category=self.category,
                        resolution_method=ResolutionMethod.PROVIDER_ADAPTER,
                        redirect_count=1,
                        status=Status.RESOLVED,
                    )

        try:
            resp, html = await client.fetch_head_or_get(url, timeout=self.timeout)
            if "g-recaptcha" in html or "cf-turnstile" in html:
                return ResolutionResponse(
                    success=False,
                    original_url=url,
                    provider=self.name,
                    category=self.category,
                    resolution_method=self.resolution_method,
                    status=Status.BLOCKED,
                    error="Link is gated by CAPTCHA verification.",
                )

            # Look for script variable or direct destination link
            match = re.search(r'var\s+(?:link|dest|target_url)\s*=\s*["\']([^"\']+)["\']', html)
            if match:
                decoded = decode_embedded_url(match.group(1))
                if decoded and not any(d in decoded for d in self.domains):
                    return ResolutionResponse(
                        success=True,
                        original_url=url,
                        destination_url=decoded,
                        provider=self.name,
                        category=self.category,
                        resolution_method=ResolutionMethod.INTERMEDIATE_PAGE,
                        redirect_count=1,
                        status=Status.RESOLVED,
                    )

            return ResolutionResponse(
                success=False,
                original_url=url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                status=Status.UNSUPPORTED,
                error="Destination requires manual step progression.",
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


class UnlockGateProvider(BaseProvider):
    """Sub2Unlock and Social Unlock gate resolver.
    
    Many social-unlock links store the destination URL directly in the page HTML
    or data attributes for client-side redirection once actions are clicked.
    """

    id: str = "unlock_gate"
    name: str = "Sub2Unlock / Social Unlock"
    category: Category = Category.ADVERTISING
    compatibility: CompatibilityState = CompatibilityState.SUPPORTED
    domains: list[str] = [
        "sub2unlock.com",
        "sub2unlock.net",
        "sub2unlock.io",
        "social-unlock.com",
        "boost.ink",
    ]
    description: str = "Extracts destination URLs embedded in public social-unlock pages."
    resolution_method: ResolutionMethod = ResolutionMethod.DIRECT_LINK_EXTRACTION

    async def resolve(self, url: str, client: SafeHttpClient) -> ResolutionResponse:
        parsed = urlsplit(url)
        query = parse_qs(parsed.query)

        for param in ("url", "dest", "link", "target"):
            if param in query:
                decoded = decode_embedded_url(query[param][0])
                if decoded:
                    return ResolutionResponse(
                        success=True,
                        original_url=url,
                        destination_url=decoded,
                        provider=self.name,
                        category=self.category,
                        resolution_method=ResolutionMethod.PROVIDER_ADAPTER,
                        redirect_count=1,
                        status=Status.RESOLVED,
                    )

        try:
            resp, html = await client.fetch_head_or_get(url, timeout=self.timeout)
            soup = BeautifulSoup(html, "html.parser")

            # Check for data-url, data-link, or href in unlock button
            target_elem = soup.find(attrs={"data-url": True}) or soup.find(attrs={"data-link": True})
            if target_elem:
                raw_dest = target_elem.get("data-url") or target_elem.get("data-link")
                decoded = decode_embedded_url(raw_dest)
                if decoded:
                    return ResolutionResponse(
                        success=True,
                        original_url=url,
                        destination_url=decoded,
                        provider=self.name,
                        category=self.category,
                        resolution_method=ResolutionMethod.DIRECT_LINK_EXTRACTION,
                        redirect_count=1,
                        status=Status.RESOLVED,
                    )

            # Look for JS destination assignment
            match = re.search(r'(?:destination|targetUrl|unlockUrl|unlocked_link)\s*[:=]\s*["\']([^"\']+)["\']', html)
            if match:
                decoded = decode_embedded_url(match.group(1))
                if decoded and not any(d in decoded for d in self.domains):
                    return ResolutionResponse(
                        success=True,
                        original_url=url,
                        destination_url=decoded,
                        provider=self.name,
                        category=self.category,
                        resolution_method=ResolutionMethod.DIRECT_LINK_EXTRACTION,
                        redirect_count=1,
                        status=Status.RESOLVED,
                    )

            return ResolutionResponse(
                success=False,
                original_url=url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                status=Status.UNSUPPORTED,
                error="Could not locate public unlock destination in page source.",
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


class Move2LinkProvider(BaseProvider):
    """Move2Link shortlink resolver for move2link.com and go.move2link.co.
    
    Resolves advertising shortlinks via query parameter decoding,
    redirect chain tracking, and public DOM / script inspection.
    """

    id: str = "move2link"
    name: str = "Move2Link"
    category: Category = Category.ADVERTISING
    compatibility: CompatibilityState = CompatibilityState.PARTIAL
    domains: list[str] = [
        "move2link.com",
        "move2link.co",
        "go.move2link.co",
        "move2link.net",
        "move2link.cc",
        "move2link.org",
    ]
    description: str = (
        "Resolves Move2Link advertising shortlinks via parameter decoding, "
        "public DOM extraction, and redirect inspection."
    )
    resolution_method: ResolutionMethod = ResolutionMethod.PROVIDER_ADAPTER

    async def resolve(self, url: str, client: SafeHttpClient) -> ResolutionResponse:
        parsed = urlsplit(url)
        query = parse_qs(parsed.query)

        # 1. Inspect query parameters for embedded destinations (plain, URL-encoded, or base64)
        for param in ("r", "dest", "target", "url", "link", "to", "redirect"):
            if param in query:
                decoded = decode_embedded_url(query[param][0])
                if decoded and not any(d in decoded for d in self.domains):
                    return ResolutionResponse(
                        success=True,
                        original_url=url,
                        destination_url=decoded,
                        provider=self.name,
                        category=self.category,
                        resolution_method=ResolutionMethod.PROVIDER_ADAPTER,
                        redirect_count=1,
                        status=Status.RESOLVED,
                    )

        # 2. Safely follow redirect chain and fetch intermediate page
        try:
            final_url, trace, html, last_resp = await client.follow_redirect_chain(
                url, timeout=self.timeout
            )
            final_parsed = urlsplit(final_url)
            final_host = (final_parsed.hostname or "").lower()

            # If redirects already led to an external destination
            if not any(d in final_host or final_host.endswith("." + d) for d in self.domains):
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

            status_code = last_resp.status_code if last_resp else 200
            if status_code in (404, 410):
                return ResolutionResponse(
                    success=False,
                    original_url=url,
                    provider=self.name,
                    category=self.category,
                    resolution_method=self.resolution_method,
                    status=Status.EXPIRED,
                    error="Move2Link shortlink not found or expired.",
                    trace=[h.to_dict() for h in trace],
                )

            if html:
                # Check for CAPTCHA, Turnstile, or paywall challenge
                if (
                    "cf-turnstile" in html
                    or "g-recaptcha" in html
                    or "h-captcha" in html
                    or "sell-link" in html
                    or "qris" in html
                ):
                    return ResolutionResponse(
                        success=False,
                        original_url=url,
                        provider=self.name,
                        category=self.category,
                        resolution_method=self.resolution_method,
                        status=Status.BLOCKED,
                        error=(
                            "Move2Link destination is protected by an interactive security "
                            "verification or digital paywall. Automated circumvention of access controls is prohibited."
                        ),
                        trace=[h.to_dict() for h in trace],
                    )

                # Check for HTML meta refresh
                meta_url = self.extract_meta_refresh(html)
                if meta_url:
                    decoded_meta = decode_embedded_url(meta_url)
                    if decoded_meta and not any(d in decoded_meta for d in self.domains):
                        return ResolutionResponse(
                            success=True,
                            original_url=url,
                            destination_url=decoded_meta,
                            provider=self.name,
                            category=self.category,
                            resolution_method=ResolutionMethod.HTML_META_REFRESH,
                            redirect_count=max(1, len(trace)),
                            status=Status.RESOLVED,
                            trace=[h.to_dict() for h in trace],
                        )

                # Check canonical or og:url
                canonical = self.extract_canonical_or_og_url(html)
                if canonical and not any(d in canonical for d in self.domains):
                    return ResolutionResponse(
                        success=True,
                        original_url=url,
                        destination_url=canonical,
                        provider=self.name,
                        category=self.category,
                        resolution_method=ResolutionMethod.INTERMEDIATE_PAGE,
                        redirect_count=max(1, len(trace)),
                        status=Status.RESOLVED,
                        trace=[h.to_dict() for h in trace],
                    )

                # Parse DOM for download / continue button with target URL
                soup = BeautifulSoup(html, "html.parser")
                btn = (
                    soup.find("a", id="getlink")
                    or soup.find("a", class_="get-link")
                    or soup.find("a", id="btn-main")
                    or soup.find("a", attrs={"data-url": True})
                    or soup.find("a", attrs={"data-href": True})
                )
                if btn:
                    raw_href = btn.get("href") or btn.get("data-url") or btn.get("data-href")
                    decoded_href = decode_embedded_url(raw_href)
                    if decoded_href and not any(d in decoded_href for d in self.domains):
                        return ResolutionResponse(
                            success=True,
                            original_url=url,
                            destination_url=decoded_href,
                            provider=self.name,
                            category=self.category,
                            resolution_method=ResolutionMethod.INTERMEDIATE_PAGE,
                            redirect_count=max(1, len(trace)),
                            status=Status.RESOLVED,
                            trace=[h.to_dict() for h in trace],
                        )

                # Check for JavaScript variables or redirection assignments
                match = re.search(
                    r'(?:var|let|const)\s+(?:link|dest|target|target_url|go_url|redirect_url|url)\s*=\s*["\']([^"\']+)["\']',
                    html,
                )
                if match:
                    decoded_js = decode_embedded_url(match.group(1))
                    if decoded_js and not any(d in decoded_js for d in self.domains):
                        return ResolutionResponse(
                            success=True,
                            original_url=url,
                            destination_url=decoded_js,
                            provider=self.name,
                            category=self.category,
                            resolution_method=ResolutionMethod.INTERMEDIATE_PAGE,
                            redirect_count=max(1, len(trace)),
                            status=Status.RESOLVED,
                            trace=[h.to_dict() for h in trace],
                        )

                # Check for atob decoded strings
                atob_match = re.search(r'atob\(["\']([A-Za-z0-9+/=]+)["\']\)', html)
                if atob_match:
                    decoded_atob = decode_embedded_url(atob_match.group(1))
                    if decoded_atob and not any(d in decoded_atob for d in self.domains):
                        return ResolutionResponse(
                            success=True,
                            original_url=url,
                            destination_url=decoded_atob,
                            provider=self.name,
                            category=self.category,
                            resolution_method=ResolutionMethod.INTERMEDIATE_PAGE,
                            redirect_count=max(1, len(trace)),
                            status=Status.RESOLVED,
                            trace=[h.to_dict() for h in trace],
                        )

            return ResolutionResponse(
                success=False,
                original_url=url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                status=Status.UNSUPPORTED,
                error=(
                    "Move2Link intermediate ad-wall requires interactive steps that "
                    "cannot be resolved statically."
                ),
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

