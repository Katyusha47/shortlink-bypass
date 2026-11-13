"""Generic HTTP Redirect Resolver for any standard shortener or redirect link."""

from __future__ import annotations
from urllib.parse import urljoin
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


class GenericRedirectProvider(BaseProvider):
    """Generic fallback provider that follows HTTP redirects and meta-refresh tags."""

    id: str = "generic_redirect"
    name: str = "Generic Redirect Resolver"
    category: Category = Category.GENERIC_REDIRECT
    compatibility: CompatibilityState = CompatibilityState.SUPPORTED
    domains: list[str] = []
    description: str = "Follows safe HTTP redirect chains (301, 302, 307, 308) and HTML meta refresh tags."
    resolution_method: ResolutionMethod = ResolutionMethod.HTTP_REDIRECT

    def can_handle(self, url: str) -> bool:
        # Generic provider can handle any URL as fallback
        return True

    async def resolve(
        self,
        url: str,
        client: SafeHttpClient,
    ) -> ResolutionResponse:
        try:
            final_url, trace, html_content, last_resp = await client.follow_redirect_chain(
                start_url=url,
                timeout=self.timeout,
            )

            # Check if there is an HTML meta-refresh in the final content
            if html_content:
                meta_dest = self.extract_meta_refresh(html_content)
                if meta_dest:
                    meta_url = urljoin(final_url, meta_dest)
                    # Follow that meta redirect one step further
                    meta_final, meta_trace, _, meta_last = await client.follow_redirect_chain(
                        start_url=meta_url,
                        timeout=self.timeout,
                    )
                    final_url = meta_final
                    trace.extend(meta_trace)
                    last_resp = meta_last

            hop_dicts = [h.to_dict() for h in trace]
            redirect_count = max(0, len(trace) - 1)

            # Verify if destination is different or valid
            status_code = last_resp.status_code if last_resp else 200
            if status_code in (404, 410):
                return ResolutionResponse(
                    success=False,
                    original_url=url,
                    destination_url=final_url if final_url != url else None,
                    provider=self.name,
                    category=self.category,
                    resolution_method=self.resolution_method,
                    redirect_count=redirect_count,
                    status=Status.EXPIRED if status_code == 410 else Status.INACCESSIBLE,
                    error=f"Destination returned HTTP status {status_code}.",
                    trace=hop_dicts,
                )

            if status_code >= 400:
                return ResolutionResponse(
                    success=False,
                    original_url=url,
                    destination_url=final_url,
                    provider=self.name,
                    category=self.category,
                    resolution_method=self.resolution_method,
                    redirect_count=redirect_count,
                    status=Status.INACCESSIBLE,
                    error=f"Destination returned error HTTP {status_code}.",
                    trace=hop_dicts,
                )

            return ResolutionResponse(
                success=True,
                original_url=url,
                destination_url=final_url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                redirect_count=redirect_count,
                status=Status.RESOLVED,
                trace=hop_dicts,
            )

        except SSRFSecurityError as exc:
            return ResolutionResponse(
                success=False,
                original_url=url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                status=Status.BLOCKED,
                error=f"Security restriction: {exc}",
            )
        except InvalidURLError as exc:
            return ResolutionResponse(
                success=False,
                original_url=url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                status=Status.INVALID_URL,
                error=str(exc),
            )
        except TimeoutError as exc:
            return ResolutionResponse(
                success=False,
                original_url=url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                status=Status.TIMEOUT,
                error=str(exc),
            )
        except Exception as exc:
            return ResolutionResponse(
                success=False,
                original_url=url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                status=Status.PROVIDER_ERROR,
                error=f"Unexpected error: {exc}",
            )

