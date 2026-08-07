"""Drop-in conftest that retargets backend/tests/ at a live URL.

The stock `backend/tests/conftest.py` uses `httpx.ASGITransport(app=app)` so
tests exercise the FastAPI app in-process. For parity soak we want the same
tests to exercise a *live* HTTP server — either the Python backend at
:8000 or the Rust backend at :8001.

Usage:

    PARITY_BASE_URL=http://localhost:8001 \\
        pytest backend/tests/ --override-conftest backend-rs/tests/parity/python_tests_conftest.py

This file only replaces the `async_client` fixture. Every other fixture
(`test_user`, `test_org`, `user_token`, etc.) is imported unchanged from
the stock conftest so we don't drift on them.
"""

from __future__ import annotations

import os
from typing import AsyncGenerator

import pytest_asyncio
from httpx import AsyncClient

# Re-export every fixture from the stock conftest except `async_client`.
# We import it as a module and filter.
import backend.tests.conftest as _stock  # type: ignore

for _name in dir(_stock):
    if _name.startswith("_") or _name == "async_client":
        continue
    globals()[_name] = getattr(_stock, _name)


BASE_URL = os.environ.get("PARITY_BASE_URL", "http://localhost:8000")


@pytest_asyncio.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:  # type: ignore[override]
    """Live-URL client shared by every test in `backend/tests/`."""
    async with AsyncClient(base_url=BASE_URL) as client:
        yield client
