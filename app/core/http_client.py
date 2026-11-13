"""Safe HTTP Client with per-hop redirect validation, SSRF defense, and size limits."""

from __future__ import annotations
import asyncio
from typing import List, Optional, Tuple, Dict, Any
from urllib.parse import urljoin, urlsplit
import httpx

from app.config import settings
from app.core.security import verify_target_safety, SSRFSecurityError, InvalidURLError


class HopResult:
    """Represents a single step in a redirect chain."""
    def __init__(
        self,
        url: str,
        status_code: int,
        headers: Dict[str, str],
        ip: Optional[str] = None,
        location: Optional[str] = None,
    ):
        self.url = url
        self.status_code = status_code
        self.headers = headers
        self.ip = ip
        self.location = location

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "location": self.location,
            "ip": self.ip,
        }


class SafeHttpClient:
    """HTTP client enforcing per-hop SSRF validation, body caps, and redirect controls."""

    def __init__(self, timeout: float = settings.DEFAULT_TIMEOUT_SECONDS):
        self.timeout = timeout
        self.headers = {
            "User-Agent": settings.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
        }

    async def fetch_head_or_get(
        self,
        url: str,
        timeout: Optional[float] = None,
        custom_headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[httpx.Response, str]:
        """Safely fetch a URL after validating IP safety, enforcing max body size.
        
        Returns (response, body_text).
        """
        request_timeout = timeout or self.timeout
        normalized_url, _, resolved_ips = verify_target_safety(url)
        primary_ip = resolved_ips[0] if resolved_ips else ""

        headers = dict(self.headers)
        if custom_headers:
            headers.update(custom_headers)

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(request_timeout),
            follow_redirects=False,
            verify=True,
        ) as client:
            # Stream the response to enforce MAX_RESPONSE_BODY_BYTES
            async with client.stream("GET", normalized_url, headers=headers) as resp:
                content_chunks = []
                bytes_read = 0
                max_bytes = settings.MAX_RESPONSE_BODY_BYTES

                async for chunk in resp.aiter_bytes():
                    bytes_read += len(chunk)
                    if bytes_read > max_bytes:
                        # Truncate content safely to avoid memory exhaustion
                        remaining = max_bytes - (bytes_read - len(chunk))
                        if remaining > 0:
                            content_chunks.append(chunk[:remaining])
                        break
                    content_chunks.append(chunk)

                body_bytes = b"".join(content_chunks)
                # Attempt decoding
                encoding = resp.encoding or "utf-8"
                try:
                    text_content = body_bytes.decode(encoding, errors="replace")
                except Exception:
                    text_content = body_bytes.decode("utf-8", errors="replace")

                # Build a pseudo response object or return response with loaded text
                resp._content = body_bytes
                return resp, text_content

    async def follow_redirect_chain(
        self,
        start_url: str,
        max_hops: int = settings.MAX_REDIRECT_HOPS,
        timeout: Optional[float] = None,
        custom_headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[str, List[HopResult], Optional[str], Optional[httpx.Response]]:
        """Follow HTTP redirect chain hop-by-hop with per-hop SSRF validation.
        
        Returns:
            (final_url, hop_trace, final_html_content, last_response)
        """
        current_url = start_url
        visited_urls: set[str] = set()
        trace: List[HopResult] = []
        hop_count = 0
        last_resp: Optional[httpx.Response] = None
        final_content: Optional[str] = None

        request_timeout = timeout or self.timeout

        headers = dict(self.headers)
        if custom_headers:
            headers.update(custom_headers)

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(request_timeout),
            follow_redirects=False,
            verify=True,
        ) as client:
            while hop_count < max_hops:
                # 1. Validate target safety at EVERY hop (SSRF & DNS rebinding defense)
                normalized_url, hostname, resolved_ips = verify_target_safety(current_url)
                primary_ip = resolved_ips[0] if resolved_ips else "unknown"

                # 2. Check for redirect loops
                if normalized_url in visited_urls:
                    raise InvalidURLError(f"Redirect loop detected at '{normalized_url}'.")
                visited_urls.add(normalized_url)

                # 3. Perform request (HEAD first for efficiency if not start, or GET with stream)
                # We use GET stream to safely capture headers and redirect locations
                try:
                    async with client.stream("GET", normalized_url, headers=headers) as resp:
                        last_resp = resp
                        status = resp.status_code
                        location = resp.headers.get("location")

                        # Record this hop
                        hop = HopResult(
                            url=normalized_url,
                            status_code=status,
                            headers=dict(resp.headers),
                            ip=primary_ip,
                            location=location,
                        )
                        trace.append(hop)

                        # Check if this is a redirect
                        if status in (301, 302, 303, 307, 308) and location:
                            # Strip sensitive headers across domain boundaries
                            target_next = urljoin(normalized_url, location)
                            next_parsed = urlsplit(target_next)
                            current_parsed = urlsplit(normalized_url)
                            if next_parsed.netloc.lower() != current_parsed.netloc.lower():
                                headers.pop("Authorization", None)
                                headers.pop("Cookie", None)

                            current_url = target_next
                            hop_count += 1
                            continue

                        # Terminal non-redirect status reached (200, 404, etc.)
                        # Read body safely up to limit
                        content_chunks = []
                        bytes_read = 0
                        max_bytes = settings.MAX_RESPONSE_BODY_BYTES

                        async for chunk in resp.aiter_bytes():
                            bytes_read += len(chunk)
                            if bytes_read > max_bytes:
                                break
                            content_chunks.append(chunk)

                        body_bytes = b"".join(content_chunks)
                        encoding = resp.encoding or "utf-8"
                        try:
                            final_content = body_bytes.decode(encoding, errors="replace")
                        except Exception:
                            final_content = body_bytes.decode("utf-8", errors="replace")

                        return normalized_url, trace, final_content, resp

                except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as exc:
                    raise TimeoutError(f"Connection timed out while resolving '{normalized_url}': {exc}")
                except httpx.RequestError as exc:
                    raise InvalidURLError(f"HTTP request failed for '{normalized_url}': {exc}")

            # Exceeded max hops
            return current_url, trace, final_content, last_resp

