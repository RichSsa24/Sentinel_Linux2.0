"""The hardened, authenticated read API."""

from __future__ import annotations

from sentinel.api.app import create_app
from sentinel.api.security import require_api_key

__all__ = ["create_app", "require_api_key"]
