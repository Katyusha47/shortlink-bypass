"""Tests for Provider Registry, Category A, Category B, and Category C Adapters."""

import asyncio
from app.engine.registry import registry
from app.engine.models import Category, Status, ResolutionMethod
from app.engine.providers.traditional import (
    BitlyProvider,
    TinyUrlProvider,
    IsGdProvider,
    TcoProvider,
    RebrandlyProvider,
)
from app.engine.providers.advertising import (
    LinkvertiseProvider,
    LootLabsProvider,
    OuoIoProvider,
    UnlockGateProvider,
    Move2LinkProvider,
    decode_embedded_url,
)
from app.engine.providers.download_gates import (
    MediaFireProvider,
    GoogleDriveProvider,
    DropboxProvider,
    format_bytes,
)
from app.engine.providers.generic import GenericRedirectProvider
from app.core.http_client import SafeHttpClient, HopResult


def test_provider_registry_lookup():
    assert isinstance(registry.find_provider_for_url("https://bit.ly/abc"), BitlyProvider)
    assert isinstance(registry.find_provider_for_url("https://tinyurl.com/xyz"), TinyUrlProvider)
    assert isinstance(registry.find_provider_for_url("https://is.gd/123"), IsGdProvider)
    assert isinstance(registry.find_provider_for_url("https://t.co/xyz"), TcoProvider)
    assert isinstance(registry.find_provider_for_url("https://mediafire.com/file/abc"), MediaFireProvider)
    assert isinstance(registry.find_provider_for_url("https://drive.google.com/file/d/123"), GoogleDriveProvider)
    assert isinstance(registry.find_provider_for_url("https://linkvertise.com/123"), LinkvertiseProvider)
    assert isinstance(registry.find_provider_for_url("https://go.move2link.co/abc"), Move2LinkProvider)
    assert isinstance(registry.find_provider_for_url("https://move2link.com/xyz"), Move2LinkProvider)
    assert isinstance(registry.find_provider_for_url("https://unknown-shortener.xyz/abc"), GenericRedirectProvider)


def test_decode_embedded_url():
    assert decode_embedded_url("https://example.com/dest") == "https://example.com/dest"
    assert decode_embedded_url("https%3A%2F%2Fexample.com%2Ftarget") == "https://example.com/target"
    import base64
    b64 = base64.b64encode(b"https://destination.org/final").decode("utf-8")
    assert decode_embedded_url(b64) == "https://destination.org/final"
    assert decode_embedded_url("not-a-url") is None


def test_format_bytes():
    assert format_bytes(500) == "500 B"
    assert format_bytes(2048) == "2.0 KB"
    assert format_bytes(1024 * 1024 * 5) == "5.00 MB"


# --- Category A: Traditional Tests ---

def test_bitly_provider_mock(monkeypatch):
    provider = BitlyProvider()
    client = SafeHttpClient()

    async def mock_follow(start_url, timeout=None):
        return (
            "https://target.com/landing",
            [
                HopResult(url=start_url, status_code=301, headers={"location": "https://target.com/landing"}),
                HopResult(url="https://target.com/landing", status_code=200, headers={}),
            ],
            None,
            None,
        )

    monkeypatch.setattr(client, "follow_redirect_chain", mock_follow)
    result = asyncio.run(provider.resolve("https://bit.ly/example", client))

    assert result.success is True
    assert result.destination_url == "https://target.com/landing"
    assert result.status == Status.RESOLVED
    assert result.category == Category.TRADITIONAL
    assert result.redirect_count == 1


def test_isgd_provider_api_lookup(monkeypatch):
    provider = IsGdProvider()
    client = SafeHttpClient()

    class MockResp:
        status_code = 200

    async def mock_fetch(url, timeout=None):
        return MockResp(), '{"url": "https://final-dest.org/docs"}'

    monkeypatch.setattr(client, "fetch_head_or_get", mock_fetch)
    result = asyncio.run(provider.resolve("https://is.gd/abcde", client))

    assert result.success is True
    assert result.destination_url == "https://final-dest.org/docs"
    assert result.resolution_method == ResolutionMethod.API_LOOKUP
    assert result.status == Status.RESOLVED


def test_tco_provider_meta_refresh(monkeypatch):
    provider = TcoProvider()
    client = SafeHttpClient()

    html_with_meta = """
    <html><head>
    <noscript><META http-equiv="refresh" content="0;URL=https://news.ycombinator.com/"></noscript>
    </head><body></body></html>
    """

    async def mock_follow(start_url, timeout=None):
        return (
            "https://t.co/abc",
            [HopResult(url=start_url, status_code=200, headers={})],
            html_with_meta,
            None,
        )

    monkeypatch.setattr(client, "follow_redirect_chain", mock_follow)
    result = asyncio.run(provider.resolve("https://t.co/abc", client))

    assert result.success is True
    assert result.destination_url == "https://news.ycombinator.com/"
    assert result.status == Status.RESOLVED


# --- Category B: Advertising Tests ---

def test_linkvertise_query_param():
    provider = LinkvertiseProvider()
    client = SafeHttpClient()

    import base64
    dest = "https://example.com/unlocked-content"
    b64_dest = base64.b64encode(dest.encode()).decode()
    url = f"https://linkvertise.com/123/test?r={b64_dest}"

    result = asyncio.run(provider.resolve(url, client))
    assert result.success is True
    assert result.destination_url == dest
    assert result.category == Category.ADVERTISING
    assert result.status == Status.RESOLVED


def test_linkvertise_cloudflare_captcha_blocked(monkeypatch):
    provider = LinkvertiseProvider()
    client = SafeHttpClient()

    class MockResp:
        status_code = 403

    async def mock_fetch(url, timeout=None):
        return MockResp(), '<html><div class="cf-turnstile">Please verify you are human</div></html>'

    monkeypatch.setattr(client, "fetch_head_or_get", mock_fetch)
    result = asyncio.run(provider.resolve("https://linkvertise.com/gated-link", client))

    assert result.success is False
    assert result.status == Status.BLOCKED
    assert "interactive security challenge" in (result.error or "").lower()


def test_unlock_gate_html_data_attribute(monkeypatch):
    provider = UnlockGateProvider()
    client = SafeHttpClient()

    html = """
    <html>
      <body>
        <button id="unlock-btn" data-url="https://github.com/my-repo">Unlock Link</button>
      </body>
    </html>
    """

    class MockResp:
        status_code = 200

    async def mock_fetch(url, timeout=None):
        return MockResp(), html

    monkeypatch.setattr(client, "fetch_head_or_get", mock_fetch)
    result = asyncio.run(provider.resolve("https://sub2unlock.com/abc", client))

    assert result.success is True
    assert result.destination_url == "https://github.com/my-repo"
    assert result.status == Status.RESOLVED


# --- Category C: Download Gate Tests ---

def test_mediafire_provider_direct_link(monkeypatch):
    provider = MediaFireProvider()
    client = SafeHttpClient()

    mediafire_html = """
    <html>
      <body>
        <a class="popsok input" id="downloadButton" href="https://download123.mediafire.com/token/test_file.zip">
          Download (15.2 MB)
        </a>
      </body>
    </html>
    """

    class MockLandingResp:
        status_code = 200

    class MockHeadResp:
        status_code = 200
        headers = {
            "content-length": "15938355",
            "content-type": "application/zip",
            "content-disposition": 'attachment; filename="test_file.zip"',
        }

    async def mock_fetch(url, timeout=None):
        if "download123.mediafire.com" in url:
            return MockHeadResp(), ""
        return MockLandingResp(), mediafire_html

    monkeypatch.setattr(client, "fetch_head_or_get", mock_fetch)
    result = asyncio.run(provider.resolve("https://www.mediafire.com/file/abc123xyz/test_file.zip/file", client))

    assert result.success is True
    assert result.destination_url == "https://download123.mediafire.com/token/test_file.zip"
    assert result.category == Category.DOWNLOAD_GATE
    assert result.status == Status.RESOLVED
    assert result.metadata is not None
    assert result.metadata["is_direct_download"] is True
    assert result.metadata["filename"] == "test_file.zip"
    assert "15.20 MB" in result.metadata["file_size_formatted"]


def test_google_drive_provider():
    provider = GoogleDriveProvider()
    client = SafeHttpClient()

    url = "https://drive.google.com/file/d/1ABCXYZ-test12345/view?usp=sharing"
    result = asyncio.run(provider.resolve(url, client))

    assert result.success is True
    assert result.destination_url == "https://drive.google.com/uc?export=download&id=1ABCXYZ-test12345"
    assert result.category == Category.DOWNLOAD_GATE
    assert result.metadata["is_direct_download"] is True


def test_dropbox_provider():
    provider = DropboxProvider()
    client = SafeHttpClient()

    url = "https://www.dropbox.com/s/xyz123/document.pdf?dl=0"
    result = asyncio.run(provider.resolve(url, client))

    assert result.success is True
    assert "dl=1" in result.destination_url
    assert result.category == Category.DOWNLOAD_GATE
    assert result.metadata["is_direct_download"] is True


# --- Move2Link Provider Tests ---

def test_move2link_query_parameter_decoding():
    provider = Move2LinkProvider()
    client = SafeHttpClient()

    import base64
    dest = "https://example.com/target-download"
    b64_dest = base64.b64encode(dest.encode()).decode()
    url = f"https://go.move2link.co/link123?r={b64_dest}"

    result = asyncio.run(provider.resolve(url, client))
    assert result.success is True
    assert result.destination_url == dest
    assert result.category == Category.ADVERTISING
    assert result.status == Status.RESOLVED


def test_move2link_redirect_chain(monkeypatch):
    provider = Move2LinkProvider()
    client = SafeHttpClient()

    async def mock_follow(start_url, timeout=None):
        return (
            "https://mega.nz/file/sample123",
            [
                HopResult(url=start_url, status_code=302, headers={"location": "https://mega.nz/file/sample123"}),
                HopResult(url="https://mega.nz/file/sample123", status_code=200, headers={}),
            ],
            None,
            None,
        )

    monkeypatch.setattr(client, "follow_redirect_chain", mock_follow)
    result = asyncio.run(provider.resolve("https://go.move2link.co/download", client))

    assert result.success is True
    assert result.destination_url == "https://mega.nz/file/sample123"
    assert result.status == Status.RESOLVED
    assert result.redirect_count == 1


def test_move2link_dom_parsing(monkeypatch):
    provider = Move2LinkProvider()
    client = SafeHttpClient()

    move2link_html = """
    <html>
      <body>
        <div class="container">
          <a id="getlink" href="https://mediafire.com/file/mydata.zip" class="btn btn-success">
            Get Link
          </a>
        </div>
      </body>
    </html>
    """

    class MockResp:
        status_code = 200

    async def mock_follow(start_url, timeout=None):
        return (
            "https://go.move2link.co/wait-page",
            [HopResult(url=start_url, status_code=200, headers={})],
            move2link_html,
            MockResp(),
        )

    monkeypatch.setattr(client, "follow_redirect_chain", mock_follow)
    result = asyncio.run(provider.resolve("https://go.move2link.co/wait-page", client))

    assert result.success is True
    assert result.destination_url == "https://mediafire.com/file/mydata.zip"
    assert result.status == Status.RESOLVED


def test_move2link_captcha_blocked(monkeypatch):
    provider = Move2LinkProvider()
    client = SafeHttpClient()

    html_captcha = """
    <html>
      <body>
        <div class="g-recaptcha" data-sitekey="abc"></div>
        <p>Please solve the verification challenge</p>
      </body>
    </html>
    """

    class MockResp:
        status_code = 200

    async def mock_follow(start_url, timeout=None):
        return (
            "https://go.move2link.co/captcha-gate",
            [HopResult(url=start_url, status_code=200, headers={})],
            html_captcha,
            MockResp(),
        )

    monkeypatch.setattr(client, "follow_redirect_chain", mock_follow)
    result = asyncio.run(provider.resolve("https://go.move2link.co/captcha-gate", client))

    assert result.success is False
    assert result.status == Status.BLOCKED
    assert "interactive security verification" in (result.error or "").lower()

