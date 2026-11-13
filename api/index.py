"""Vercel serverless entrypoint for FastAPI application."""

import sys
from pathlib import Path

# Ensure root workspace directory is in python path for module imports
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.main import app

# Vercel ASGI handler looks for `app`

