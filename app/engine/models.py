"""Data models and enums for shortlink resolution engine."""

from __future__ import annotations
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class Category(str, Enum):
    TRADITIONAL = "traditional"
    ADVERTISING = "advertising"
    DOWNLOAD_GATE = "download_gate"
    GENERIC_REDIRECT = "generic_redirect"


class Status(str, Enum):
    RESOLVED = "resolved"
    UNSUPPORTED = "unsupported"
    EXPIRED = "expired"
    INACCESSIBLE = "inaccessible"
    BLOCKED = "blocked"
    TIMEOUT = "timeout"
    INVALID_URL = "invalid_url"
    PROVIDER_ERROR = "provider_error"


class CompatibilityState(str, Enum):
    SUPPORTED = "supported"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"


class ResolutionMethod(str, Enum):
    PROVIDER_ADAPTER = "provider_adapter"
    HTTP_REDIRECT = "http_redirect"
    HTML_META_REFRESH = "html_meta_refresh"
    INTERMEDIATE_PAGE = "intermediate_page"
    API_LOOKUP = "api_lookup"
    DIRECT_LINK_EXTRACTION = "direct_link_extraction"


class ProviderInfo(BaseModel):
    id: str
    name: str
    category: Category
    compatibility: CompatibilityState
    domains: List[str]
    description: str
    resolution_method: ResolutionMethod


class ResolutionRequest(BaseModel):
    url: str = Field(..., description="Shortened URL to resolve", min_length=3, max_length=2048)


class ResolutionResponse(BaseModel):
    success: bool
    original_url: str
    destination_url: Optional[str] = None
    provider: str
    category: Category
    resolution_method: ResolutionMethod
    redirect_count: int = 0
    status: Status
    error: Optional[str] = None
    trace: Optional[List[Dict[str, Any]]] = None
    metadata: Optional[Dict[str, Any]] = None

