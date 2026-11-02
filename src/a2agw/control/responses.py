"""The control plane's JSON responses: ASCII-only JSON.

Gateway strings are stored verbatim (audit rows, health, metrics), so a gateway's chain
still verifies against its copy, and a gateway can send a lone surrogate (``"\\ud800"``).
Starlette's ``JSONResponse`` renders with ``ensure_ascii=False`` and encodes as UTF-8, which
raises on one; this one escapes every non-ASCII character instead, so any stored string can
be answered. It is the app's ``default_response_class`` and every route's explicit JSON
response."""

from __future__ import annotations

import json
from typing import Any

from a2agw.control import require_fastapi

require_fastapi()

from fastapi.responses import JSONResponse as _JSONResponse


class JSONResponse(_JSONResponse):
    def render(self, content: Any) -> bytes:
        return json.dumps(
            content, ensure_ascii=True, allow_nan=False, indent=None, separators=(",", ":")
        ).encode("ascii")
