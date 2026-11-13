"""Centralized Provider Registry for Shortlink Resolution Engine."""

from __future__ import annotations
from typing import List, Optional, Dict
from app.engine.base import BaseProvider
from app.engine.models import ProviderInfo, Category, CompatibilityState
from app.engine.providers.generic import GenericRedirectProvider
from app.engine.providers.traditional import (
    BitlyProvider,
    TinyUrlProvider,
    IsGdProvider,
    TcoProvider,
    ShortUrlAtProvider,
    RebrandlyProvider,
    CuttlyProvider,
)
from app.engine.providers.advertising import (
    LinkvertiseProvider,
    LootLabsProvider,
    OuoIoProvider,
    ExeIoProvider,
    UnlockGateProvider,
    Move2LinkProvider,
)
from app.engine.providers.download_gates import (
    MediaFireProvider,
    GoogleDriveProvider,
    DropboxProvider,
)


class ProviderRegistry:
    """Manages provider adapters, detection, and compatibility states."""

    def __init__(self):
        self._providers: Dict[str, BaseProvider] = {}
        self._generic_provider: BaseProvider = GenericRedirectProvider()
        self._register_default_providers()

    def register(self, provider: BaseProvider) -> None:
        """Register a new provider instance."""
        self._providers[provider.id] = provider

    def _register_default_providers(self) -> None:
        # Category A: Traditional
        self.register(BitlyProvider())
        self.register(TinyUrlProvider())
        self.register(IsGdProvider())
        self.register(TcoProvider())
        self.register(ShortUrlAtProvider())
        self.register(RebrandlyProvider())
        self.register(CuttlyProvider())

        # Category B: Advertising
        self.register(LinkvertiseProvider())
        self.register(LootLabsProvider())
        self.register(OuoIoProvider())
        self.register(ExeIoProvider())
        self.register(UnlockGateProvider())
        self.register(Move2LinkProvider())

        # Category C: Download Gates
        self.register(MediaFireProvider())
        self.register(GoogleDriveProvider())
        self.register(DropboxProvider())

    def get_provider_by_id(self, provider_id: str) -> Optional[BaseProvider]:
        """Lookup provider by unique identifier."""
        return self._providers.get(provider_id)

    def find_provider_for_url(self, url: str) -> BaseProvider:
        """Automatically identify and return the matching provider for a URL.
        
        Falls back to GenericRedirectProvider if no specialized provider matches.
        """
        for provider in self._providers.values():
            if provider.can_handle(url):
                return provider
        return self._generic_provider

    def list_providers(self) -> List[ProviderInfo]:
        """Return metadata list of all registered providers including generic fallback."""
        infos = [p.get_info() for p in self._providers.values()]
        infos.append(self._generic_provider.get_info())
        return infos

    def list_by_category(self, category: Category) -> List[ProviderInfo]:
        """Return providers filtered by category."""
        return [p for p in self.list_providers() if p.category == category]


# Global Registry Singleton
registry = ProviderRegistry()

