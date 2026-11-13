"""Vercel serverless entrypoint for FastAPI application."""

import sys
from pathlib import Path

# Ensure root workspace directory is in python path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.main import app as fastapi_app


class VercelPathMiddleware:
    """ASGI Middleware to normalize paths rewritten by Vercel serverless routing."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") in ("http", "websocket"):
            path = scope.get("path", "")
            for prefix in ("/api/index.py", "/api/index"):
                if path.startswith(prefix):
                    cleaned = path[len(prefix):]
                    scope["path"] = cleaned if cleaned else "/"
                    if "raw_path" in scope:
                        scope["raw_path"] = scope["path"].encode("ascii")
                    break
        await self.app(scope, receive, send)


app = VercelPathMiddleware(fastapi_app)
