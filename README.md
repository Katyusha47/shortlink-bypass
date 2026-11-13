# Universal Shortlink Bypasser

A modern, ultra-lightweight, privacy-conscious, and SEO-friendly web platform and API for resolving shortened URLs, advertising redirect gates, and file-hosting landing pages into their genuine original destinations.

---

## Key Features

- **Modular Resolution Pipeline:** Provider-based architecture where new shortlink services and gates are added cleanly as isolated adapters without modifying core logic.
- **Three Resolution Categories:**
  - **Category A (Traditional URL Shorteners):** Bitly, TinyURL, is.gd / v.gd, Twitter/X (t.co), Rebrandly, rb.gy, ShortURL.at, Cutt.ly.
  - **Category B (Advertising & Intermediate Gates):** Linkvertise, Move2Link (move2link.com, go.move2link.co), LootLabs, ouo.io, exe.io, Sub2Unlock / Social Unlock.
  - **Category C (Download Gates & File Hosts):** MediaFire (direct CDN file extraction & file size verification), Google Drive, Dropbox.
  - **Generic Fallback:** Follows HTTP redirects (301, 302, 303, 307, 308) and HTML `<meta http-equiv="refresh">` tags for any valid URL.
- **Strict Security & Per-Hop SSRF Defenses:**
  - Validates and normalizes protocols (HTTP/HTTPS only; blocks `file://`, `gopher://`, `javascript:`, `ftp://`).
  - Blocks loopback (`127.0.0.0/8`, `::1`), private networks (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), CGNAT (`100.64.0.0/10`), IPv4-mapped IPv6, and Cloud Metadata (`169.254.169.254`, `metadata.google.internal`).
  - DNS resolution and IP verification re-evaluated at **every single redirect hop**.
  - Strips sensitive headers (`Authorization`, `Cookie`) across domain boundaries.
  - Enforces maximum redirect depth and loop detection.
  - Streams and caps response bodies (2MB max) to prevent memory exhaustion / decompression bombs.
- **High Ethical Standards:**
  - Only uses legitimate, publicly accessible mechanisms.
  - Never bypasses CAPTCHAs, bot challenges (Cloudflare Turnstile, reCAPTCHA), payment requirements, or user authentication. Protected links are transparently flagged as `blocked`.
  - Zero execution of untrusted client scripts.
- **Privacy First & Stateless:**
  - No user registration required.
  - No database storage of submitted URLs.
  - No tracking pixels, Google Analytics, or third-party advertising scripts.
  - Ephemeral in-memory LRU cache with 10-minute TTL to accelerate repeated lookups safely.
- **Lightweight, Responsive UI:**
  - Built with semantic HTML5 and modern CSS (pure vanilla, zero heavyweight UI bundles).
  - Light and Dark mode with automatic system detection and persistent toggle.
  - One-click copy to clipboard with visual confirmation.
  - Accessible redirect chain inspection accordion.
- **SEO Optimized (SSR):**
  - Server-Side Rendered with Jinja2 for instant First Contentful Paint.
  - Open Graph, Twitter Cards, canonical tags, and Schema.org `WebApplication` structured data.
  - Dynamic XML sitemap (`/sitemap.xml`) and robots.txt (`/robots.txt`).

---

## Architecture Overview

```
shortlink-bypass/
├── app/
│   ├── config.py                   # Runtime configuration and environment settings
│   ├── main.py                     # FastAPI routes, security middleware, and template handlers
│   ├── core/
│   │   ├── security.py             # SSRF defense, IP verification, and URL normalizer
│   │   ├── http_client.py          # Per-hop redirect follower with body size capping
│   │   ├── rate_limiter.py         # In-memory sliding-window rate limiter
│   │   └── cache.py                # Thread-safe in-memory LRU cache with TTL
│   ├── engine/
│   │   ├── models.py               # Pydantic schemas, Category, and Status enums
│   │   ├── base.py                 # BaseProvider abstract class and HTML utilities
│   │   ├── registry.py             # Centralized provider registry
│   │   ├── pipeline.py             # 8-step resolution pipeline
│   │   └── providers/
│   │       ├── generic.py          # Generic redirect resolver fallback
│   │       ├── traditional/        # Category A: Bitly, TinyURL, IsGd, Tco, etc.
│   │       ├── advertising/        # Category B: Linkvertise, LootLabs, OuoIo, etc.
│   │       └── download_gates/     # Category C: MediaFire, Drive, Dropbox
│   ├── static/
│   │   ├── css/main.css            # Minimalist, accessible CSS design system
│   │   ├── js/app.js               # Vanilla JS client logic (5KB, zero deps)
│   │   ├── images/favicon.svg      # Vector brand icon
│   │   └── robots.txt              # Search engine directives
│   └── templates/
│       ├── base.html               # Semantic HTML5 base with SEO & JSON-LD
│       ├── index.html              # Homepage with URL resolver interface
│       ├── supported_services.html # Compatibility status table
│       ├── about.html              # Technical mission & architecture
│       ├── privacy.html            # Data handling & zero retention guarantee
│       ├── contact.html            # Provider reporting & security disclosure
│       ├── 404.html                # Custom friendly 404 page
│       ├── 500.html                # Custom friendly 500 page
│       └── sitemap.xml             # XML sitemap template
├── tests/
│   ├── test_security_ssrf.py       # SSRF & DNS rebinding unit tests
│   ├── test_pipeline.py            # Resolution pipeline & caching tests
│   ├── test_providers.py           # Category A, B, C provider adapter tests
│   ├── test_api.py                 # API integration & rate limiting tests
│   └── test_seo_pages.py           # SSR pages & SEO metadata tests
├── pyproject.toml                  # Pytest configuration
├── .env.example                    # Example environment variables
├── README.md                       # Documentation
└── run.py                          # Application startup script
```

---

## Quick Start

### Prerequisites
- Python 3.10+ (Tested on Python 3.14)

### 1. Installation
Clone the repository and install dependencies:
```bash
git clone https://github.com/example/shortlink-bypass.git
cd shortlink-bypass

# Optional: Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install requirements (all standard dependencies)
pip install fastapi uvicorn httpx beautifulsoup4 jinja2 pydantic pytest
```

### 2. Environment Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

### 3. Run the Development Server
```bash
python3 run.py
```
Or with Uvicorn directly:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
Navigate to `http://localhost:8000` in your web browser.

---

## REST API Reference

### 1. Resolve a Shortlink
- **Endpoint:** `POST /api/resolve`
- **Rate Limit:** 30 requests / minute per IP
- **Request Body:**
```json
{
  "url": "https://bit.ly/example"
}
```
- **Response Format (200 OK):**
```json
{
  "success": true,
  "original_url": "https://bit.ly/example",
  "destination_url": "https://example.com/target-page",
  "provider": "Bitly",
  "category": "traditional",
  "resolution_method": "http_redirect",
  "redirect_count": 1,
  "status": "resolved",
  "error": null,
  "trace": [
    {
      "url": "https://bit.ly/example",
      "status_code": 301,
      "location": "https://example.com/target-page",
      "ip": "67.199.248.11"
    },
    {
      "url": "https://example.com/target-page",
      "status_code": 200,
      "location": null,
      "ip": "93.184.216.34"
    }
  ],
  "metadata": null
}
```

### 2. List Supported Providers
- **Endpoint:** `GET /api/providers`
- **Response:** JSON list of all registered provider adapters, domains, and compatibility states (`supported`, `partial`, `unsupported`, `temporarily_unavailable`).

### 3. Health Check
- **Endpoint:** `GET /api/health`
- **Response:**
```json
{
  "status": "healthy",
  "app": "Universal Shortlink Bypasser",
  "version": "1.0.0"
}
```

---

## 🧪 Running Automated Tests

Run the full automated test suite with pytest:
```bash
python3 -m pytest -v
```

Test coverage includes:
- SSRF prevention (IPv4 loopback, RFC 1918 private IPs, AWS/GCP/Azure metadata, IPv6 ULA, IPv4-mapped IPv6, blocked ports).
- DNS rebinding simulations.
- Category A, B, and C provider adapters.
- Redirect chains, loops, and hop depth limits.
- Sliding window rate limiter.
- Full SEO metadata and custom error states.

---

## Security Architecture

| Security Control | Implementation |
|---|---|
| **Protocol Restriction** | Only `http://` and `https://` permitted. Blocks `file://`, `gopher://`, `javascript:`, `ftp://`. |
| **Private IP & SSRF Defense** | Strict CIDR checking across IPv4 & IPv6 loopback, private RFC 1918, CGNAT, link-local, and cloud metadata (`169.254.169.254`). |
| **DNS Rebinding Protection** | Target hostname is resolved and verified at every hop before connection is established. |
| **Cross-Origin Stripping** | Sensitive request headers (`Authorization`, `Cookie`) are stripped when redirects traverse domain boundaries. |
| **Payload Size Capping** | Max response body limit (2MB) streams and aborts oversized responses to avoid decompression bombs. |
| **HTTP Security Headers** | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1`, `Referrer-Policy: strict-origin-when-cross-origin`, strict `Content-Security-Policy`. |

---

## License
MIT License. Built for privacy, speed, and safety.

