"""FastAPI Application Entrypoint for Universal Shortlink Bypasser."""

from __future__ import annotations
from pathlib import Path
from fastapi import FastAPI, Request, Response, Depends, status
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import settings
from app.engine.models import ResolutionRequest, ResolutionResponse
from app.engine.pipeline import pipeline
from app.engine.registry import registry
from app.core.rate_limiter import check_rate_limit

# Base paths
BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=settings.APP_DESCRIPTION,
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url=None,
)

# Mount static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Jinja2 templates
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self'; "
        "connect-src 'self';"
    )
    return response


# --- HTML Pages (SSR for SEO) ---

@app.get("/", response_class=HTMLResponse)
async def page_home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "app_name": settings.APP_NAME,
            "app_description": settings.APP_DESCRIPTION,
            "site_url": settings.SITE_URL,
            "page_title": "Resolve Any Shortlink Privately & Instantly",
            "page_description": "Unmask shortened links, intermediate redirects, and download gates into direct destinations without ads, tracking, or registration.",
            "active_page": "home",
        },
    )


@app.get("/supported-services", response_class=HTMLResponse)
async def page_supported_services(request: Request):
    providers = registry.list_providers()
    return templates.TemplateResponse(
        request=request,
        name="supported_services.html",
        context={
            "app_name": settings.APP_NAME,
            "site_url": settings.SITE_URL,
            "page_title": "Supported URL Shorteners & Gate Compatibility",
            "page_description": "Comprehensive list of URL shorteners, advertising redirects, and file hosting gates supported by Universal Shortlink Bypasser.",
            "providers": providers,
            "active_page": "supported",
        },
    )


@app.get("/about", response_class=HTMLResponse)
async def page_about(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="about.html",
        context={
            "app_name": settings.APP_NAME,
            "site_url": settings.SITE_URL,
            "page_title": "About & Architecture",
            "page_description": "Learn how the Universal Shortlink Bypasser resolution engine works, our SSRF security protections, and our privacy-first philosophy.",
            "active_page": "about",
        },
    )


@app.get("/privacy", response_class=HTMLResponse)
async def page_privacy(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="privacy.html",
        context={
            "app_name": settings.APP_NAME,
            "site_url": settings.SITE_URL,
            "page_title": "Privacy Policy & Zero Data Retention Guarantee",
            "page_description": "Transparent privacy policy: No URL database storage, no registration, no tracking pixels, and stateless link unmasking.",
            "active_page": "privacy",
        },
    )


@app.get("/contact", response_class=HTMLResponse)
async def page_contact(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="contact.html",
        context={
            "app_name": settings.APP_NAME,
            "site_url": settings.SITE_URL,
            "page_title": "Contact & Security Disclosure",
            "page_description": "Report broken provider adapters, suggest new link services, or submit responsible security vulnerability disclosures.",
            "active_page": "contact",
        },
    )


# --- SEO Endpoints (Sitemap & Robots.txt) ---

@app.get("/sitemap.xml")
async def sitemap(request: Request):
    content = templates.get_template("sitemap.xml").render(site_url=settings.SITE_URL)
    return Response(content=content, media_type="application/xml")


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt():
    robots_path = STATIC_DIR / "robots.txt"
    if robots_path.exists():
        content = robots_path.read_text(encoding="utf-8")
        content = content.replace("http://localhost:8000", settings.SITE_URL)
        return PlainTextResponse(content)
    return PlainTextResponse("User-agent: *\nAllow: /\nDisallow: /api/\n")


# --- API Endpoints ---

@app.post("/api/resolve", response_model=ResolutionResponse, dependencies=[Depends(check_rate_limit)])
async def api_resolve(payload: ResolutionRequest):
    """Resolve a shortened URL through the modular resolution pipeline."""
    result = await pipeline.execute(payload.url)
    return result


@app.get("/api/providers")
async def api_list_providers():
    """Return all registered providers and their compatibility status."""
    return [p.model_dump() for p in registry.list_providers()]


@app.get("/api/health")
async def api_health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }


# --- Error Handlers ---

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    headers = dict(exc.headers) if exc.headers else {}
    if request.url.path.startswith("/api/"):
        import json
        detail = exc.detail if isinstance(exc.detail, dict) else {"error": str(exc.detail)}
        return Response(
            content=json.dumps(detail),
            status_code=exc.status_code,
            headers=headers,
            media_type="application/json",
        )
    if exc.status_code == 404:
        return templates.TemplateResponse(
            request=request,
            name="404.html",
            context={
                "app_name": settings.APP_NAME,
                "site_url": settings.SITE_URL,
                "page_title": "Page Not Found",
                "page_description": "404 Page Not Found",
                "active_page": "",
            },
            status_code=404,
            headers=headers,
        )
    return templates.TemplateResponse(
        request=request,
        name="500.html",
        context={
            "app_name": settings.APP_NAME,
            "site_url": settings.SITE_URL,
            "page_title": "Server Error",
            "page_description": "500 Server Error",
            "active_page": "",
        },
        status_code=exc.status_code,
        headers=headers,
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    if request.url.path.startswith("/api/"):
        return Response(
            content='{"error": "An internal server error occurred."}',
            status_code=500,
            media_type="application/json",
        )
    return templates.TemplateResponse(
        request=request,
        name="500.html",
        context={
            "app_name": settings.APP_NAME,
            "site_url": settings.SITE_URL,
            "page_title": "Server Error",
            "page_description": "500 Server Error",
            "active_page": "",
        },
        status_code=500,
    )
