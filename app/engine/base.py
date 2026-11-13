"""Base Provider Abstract Class for Shortlink Resolution Engine."""

from __future__ import annotations
import re
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from urllib.parse import urlsplit, parse_qs, unquote
from bs4 import BeautifulSoup

from app.engine.models import (
    Category,
    Status,
    CompatibilityState,
    ResolutionMethod,
    ResolutionResponse,
    ProviderInfo,
)
from app.core.http_client import SafeHttpClient, HopResult
from app.config import settings


class BaseProvider(ABC):
    """Abstract Base Class for all shortlink and gate resolvers."""

    id: str = "base"
    name: str = "Base Provider"
    category: Category = Category.TRADITIONAL
    compatibility: CompatibilityState = CompatibilityState.SUPPORTED
    domains: List[str] = []
    url_patterns: List[str] = []
    description: str = "Base URL resolution provider"
    resolution_method: ResolutionMethod = ResolutionMethod.HTTP_REDIRECT
    timeout: float = settings.DEFAULT_TIMEOUT_SECONDS
    custom_headers: Dict[str, str] = {}

    def get_info(self) -> ProviderInfo:
        """Return structured metadata about this provider."""
        return ProviderInfo(
            id=self.id,
            name=self.name,
            category=self.category,
            compatibility=self.compatibility,
            domains=self.domains,
            description=self.description,
            resolution_method=self.resolution_method,
        )

    def can_handle(self, url: str) -> bool:
        """Determine if this provider can handle the given URL."""
        try:
            parsed = urlsplit(url)
            hostname = (parsed.hostname or "").lower()
        except Exception:
            return False

        # Match exact domain or subdomains
        for domain in self.domains:
            domain_clean = domain.lower()
            if hostname == domain_clean or hostname.endswith("." + domain_clean):
                return True

        # Match regex patterns if configured
        for pattern in self.url_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True

        return False

    @abstractmethod
    async def resolve(
        self,
        url: str,
        client: SafeHttpClient,
    ) -> ResolutionResponse:
        """Resolve the input URL into its original destination."""
        raise NotImplementedError

    # Common utility methods for provider implementations
    @staticmethod
    def extract_meta_refresh(html: str) -> Optional[str]:
        """Extract destination URL from <meta http-equiv="refresh" content="...url=..."> tag."""
        if not html:
            return None
        soup = BeautifulSoup(html, "html.parser")
        meta = soup.find("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)})
        if not meta or not meta.get("content"):
            return None

        content = meta["content"]
        match = re.search(r"url\s*=\s*['\"]?([^'\" >]+)", content, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None

    @staticmethod
    def extract_canonical_or_og_url(html: str) -> Optional[str]:
        """Extract destination from <link rel='canonical'> or <meta property='og:url'>."""
        if not html:
            return None
        soup = BeautifulSoup(html, "html.parser")
        canonical = soup.find("link", rel=lambda x: x and x.lower() == "canonical")
        if canonical and canonical.get("href"):
            return canonical["href"].strip()

        og = soup.find("meta", property="og:url")
        if og and og.get("content"):
            return og["content"].strip()

        return None

