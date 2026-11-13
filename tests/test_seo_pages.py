"""SEO, Accessibility, and HTML Page Response Tests."""

import pytest
from starlette.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_home_page_seo(client):
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    # Meta Tags & Title
    assert "<title>" in html
    assert "Resolve Any Shortlink" in html
    assert "Privately &amp; Instantly" in html
    assert '<meta name="description"' in html
    assert '<link rel="canonical"' in html

    # OpenGraph & Twitter
    assert '<meta property="og:title"' in html
    assert '<meta property="og:description"' in html
    assert '<meta property="og:image"' in html
    assert '<meta name="twitter:card"' in html

    # Structured Data
    assert 'application/ld+json' in html
    assert '"@type": "WebApplication"' in html

    # Form & Accessible Elements
    assert 'id="resolve-form"' in html
    assert 'id="url-input"' in html
    assert 'id="submit-btn"' in html
    assert 'id="result-container"' in html

    # Security Headers
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in response.headers


def test_supported_services_page(client):
    response = client.get("/supported-services")
    assert response.status_code == 200
    html = response.text

    assert "Supported Providers & Compatibility" in html
    assert "Category A" in html
    assert "Category B" in html
    assert "Category C" in html
    assert "Bitly" in html
    assert "MediaFire" in html
    assert "Linkvertise" in html
    assert "Move2Link" in html
    assert "Security & Compliance Policy" in html


def test_about_page(client):
    response = client.get("/about")
    assert response.status_code == 200
    html = response.text

    assert "About Universal Shortlink Bypasser" in html
    assert "Modular Resolution Pipeline" in html
    assert "Strict Security & Ethical Boundaries" in html


def test_privacy_page(client):
    response = client.get("/privacy")
    assert response.status_code == 200
    html = response.text

    assert "Privacy Policy" in html
    assert "Zero Persistent URL Storage" in html
    assert "Ephemeral In-Memory Caching" in html
    assert "No Tracking Pixels or Third-Party Ads" in html


def test_contact_page(client):
    response = client.get("/contact")
    assert response.status_code == 200
    html = response.text

    assert "Contact & Security Disclosure" in html
    assert "Report a Broken Provider" in html
    assert "Security & Vulnerability Disclosure" in html


def test_sitemap_xml(client):
    response = client.get("/sitemap.xml")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/xml")
    xml = response.text

    assert "<urlset" in xml
    assert "<loc>" in xml
    assert "/supported-services" in xml
    assert "/about" in xml
    assert "/privacy" in xml
    assert "/contact" in xml


def test_robots_txt(client):
    response = client.get("/robots.txt")
    assert response.status_code == 200
    text = response.text

    assert "User-agent: *" in text
    assert "Allow: /" in text
    assert "Disallow: /api/" in text
    assert "Sitemap:" in text


def test_custom_404_error_page(client):
    response = client.get("/non-existent-page-url-12345")
    assert response.status_code == 404
    html = response.text

    assert "Page Not Found" in html
    assert "404" in html
    assert "Return to Link Resolver" in html
