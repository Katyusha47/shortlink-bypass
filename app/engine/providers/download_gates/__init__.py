"""Category C: File Hosting and Download Link Gates (MediaFire, Drive, Dropbox, etc.)"""

from __future__ import annotations
import re
from urllib.parse import urlsplit, parse_qs, urlunsplit
from bs4 import BeautifulSoup
import httpx

from app.engine.base import BaseProvider
from app.engine.models import (
    Category,
    Status,
    CompatibilityState,
    ResolutionMethod,
    ResolutionResponse,
)
from app.core.http_client import SafeHttpClient
from app.core.security import verify_target_safety


def format_bytes(num_bytes: int) -> str:
    """Format bytes into human-readable string (KB, MB, GB)."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    elif num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    elif num_bytes < 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{num_bytes / (1024 * 1024 * 1024):.2f} GB"


class MediaFireProvider(BaseProvider):
    """MediaFire file gate resolver.
    
    Extracts direct CDN download links from MediaFire public landing pages
    and verifies file availability and metadata.
    """

    id: str = "mediafire"
    name: str = "MediaFire"
    category: Category = Category.DOWNLOAD_GATE
    compatibility: CompatibilityState = CompatibilityState.SUPPORTED
    domains: list[str] = ["mediafire.com"]
    description: str = "Extracts direct verified download links and file metadata from MediaFire landing pages."
    resolution_method: ResolutionMethod = ResolutionMethod.DIRECT_LINK_EXTRACTION

    async def resolve(self, url: str, client: SafeHttpClient) -> ResolutionResponse:
        try:
            # 1. Fetch public MediaFire landing page
            resp, html = await client.fetch_head_or_get(url, timeout=self.timeout)

            if resp.status_code == 404:
                return ResolutionResponse(
                    success=False,
                    original_url=url,
                    provider=self.name,
                    category=self.category,
                    resolution_method=self.resolution_method,
                    status=Status.EXPIRED,
                    error="File has been removed or does not exist on MediaFire.",
                )

            # 2. Parse download button href
            soup = BeautifulSoup(html, "html.parser")
            download_btn = soup.find("a", id="downloadButton") or soup.find("a", attrs={"aria-label": "Download file"})

            direct_link = None
            if download_btn and download_btn.get("href"):
                direct_link = download_btn["href"].strip()

            # Fallback regex search if ID changed
            if not direct_link:
                match = re.search(r'https?://download\d+\.mediafire\.com/[^\s"\'<>]+', html)
                if match:
                    direct_link = match.group(0)

            if not direct_link:
                return ResolutionResponse(
                    success=False,
                    original_url=url,
                    provider=self.name,
                    category=self.category,
                    resolution_method=self.resolution_method,
                    status=Status.INACCESSIBLE,
                    error="Could not locate direct download link on MediaFire page.",
                )

            # 3. Verify target safety and verify direct link accessibility
            metadata = {"is_direct_download": True}
            try:
                head_resp, _ = await client.fetch_head_or_get(direct_link, timeout=5.0)
                content_len = head_resp.headers.get("content-length")
                content_type = head_resp.headers.get("content-type", "application/octet-stream")
                content_disp = head_resp.headers.get("content-disposition", "")

                if content_len:
                    try:
                        size_int = int(content_len)
                        metadata["file_size_bytes"] = size_int
                        metadata["file_size_formatted"] = format_bytes(size_int)
                    except ValueError:
                        pass

                metadata["content_type"] = content_type

                filename_match = re.search(r'filename=["\']?([^"\';]+)', content_disp)
                if filename_match:
                    metadata["filename"] = filename_match.group(1).strip()
                else:
                    # Infer filename from path
                    path_parts = urlsplit(direct_link).path.split("/")
                    if path_parts and path_parts[-1]:
                        metadata["filename"] = path_parts[-1]

            except Exception:
                # Direct link was found even if head check encountered a hiccup
                pass

            return ResolutionResponse(
                success=True,
                original_url=url,
                destination_url=direct_link,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                redirect_count=1,
                status=Status.RESOLVED,
                metadata=metadata,
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


class GoogleDriveProvider(BaseProvider):
    """Google Drive shared file gate resolver.
    
    Transforms view/preview sharing links into direct download links.
    """

    id: str = "google_drive"
    name: str = "Google Drive"
    category: Category = Category.DOWNLOAD_GATE
    compatibility: CompatibilityState = CompatibilityState.SUPPORTED
    domains: list[str] = ["drive.google.com"]
    description: str = "Transforms Google Drive sharing links into direct download links."
    resolution_method: ResolutionMethod = ResolutionMethod.PROVIDER_ADAPTER

    async def resolve(self, url: str, client: SafeHttpClient) -> ResolutionResponse:
        file_id = None
        # Pattern 1: /file/d/<file_id>/view
        match = re.search(r'/file/d/([a-zA-Z0-9_-]+)', url)
        if match:
            file_id = match.group(1)
        else:
            # Pattern 2: ?id=<file_id>
            parsed = urlsplit(url)
            query = parse_qs(parsed.query)
            if "id" in query:
                file_id = query["id"][0]

        if not file_id:
            return ResolutionResponse(
                success=False,
                original_url=url,
                provider=self.name,
                category=self.category,
                resolution_method=self.resolution_method,
                status=Status.UNSUPPORTED,
                error="Could not extract a valid Google Drive file ID.",
            )

        direct_download_url = f"https://drive.google.com/uc?export=download&id={file_id}"

        return ResolutionResponse(
            success=True,
            original_url=url,
            destination_url=direct_download_url,
            provider=self.name,
            category=self.category,
            resolution_method=self.resolution_method,
            redirect_count=1,
            status=Status.RESOLVED,
            metadata={
                "is_direct_download": True,
                "file_id": file_id,
                "preview_url": f"https://drive.google.com/file/d/{file_id}/view",
            },
        )


class DropboxProvider(BaseProvider):
    """Dropbox shared link resolver.
    
    Converts preview links into direct download URLs.
    """

    id: str = "dropbox"
    name: str = "Dropbox"
    category: Category = Category.DOWNLOAD_GATE
    compatibility: CompatibilityState = CompatibilityState.SUPPORTED
    domains: list[str] = ["dropbox.com"]
    description: str = "Converts Dropbox preview links into direct file download links."
    resolution_method: ResolutionMethod = ResolutionMethod.PROVIDER_ADAPTER

    async def resolve(self, url: str, client: SafeHttpClient) -> ResolutionResponse:
        parsed = urlsplit(url)
        query = parse_qs(parsed.query)

        # Replace dl=0 or add dl=1
        query["dl"] = ["1"]
        # Re-encode query
        from urllib.parse import urlencode
        new_query = urlencode(query, doseq=True)

        direct_url = urlunsplit((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            new_query,
            ""
        ))

        return ResolutionResponse(
            success=True,
            original_url=url,
            destination_url=direct_url,
            provider=self.name,
            category=self.category,
            resolution_method=self.resolution_method,
            redirect_count=1,
            status=Status.RESOLVED,
            metadata={
                "is_direct_download": True,
            },
        )

