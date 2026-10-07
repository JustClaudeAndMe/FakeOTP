"""
OTP Relay API
-------------
GET/POST  /sendotp/{service}?number=...&sms=...
GET       /poll
DELETE    /poll
GET       /health
"""

import itertools
import os
import re
import threading
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

# --------------------------------------------------------------------------
# Optional API key. Set the API_KEY env var to lock the whole thing down.
# If it is not set, the API is open.
# --------------------------------------------------------------------------
API_KEY = os.getenv("API_KEY")


def require_key(x_api_key: Optional[str] = Header(default=None)):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")


app = FastAPI(title="OTP Relay API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------------------------------------
# In-memory store
# --------------------------------------------------------------------------
_lock = threading.Lock()
_messages: list[dict] = []
_next_id = itertools.count(1)
MAX_STORED = 500  # keep only the newest N messages

OTP_RE = re.compile(r"\b\d{4,8}\b")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean_number(raw: str) -> str:
    """
    Normalize a phone number.

    Important: in a query string `+` is decoded as a space, so
    `?number=+244996418946` actually arrives as ` 244996418946`.
    This puts it back the way you meant it.
    """
    n = re.sub(r"[\s\-().]", "", raw or "")
    if n and not n.startswith("+"):
        n = "+" + n
    return n


def _extract_otp(sms: str) -> Optional[str]:
    """Best-effort OTP extraction. Purely informational."""
    m = OTP_RE.search(sms or "")
    return m.group(0) if m else None


# --------------------------------------------------------------------------
# Root
# --------------------------------------------------------------------------
@app.get("/")
def root():
    return {
        "name": "OTP Relay API",
        "endpoints": {
            "send": "GET/POST /sendotp/{service}?number=...&sms=...",
            "poll": "GET /poll",
            "clear": "DELETE /poll",
            "health": "GET /health",
        },
        "auth": "X-API-Key header required if API_KEY env var is set",
    }


# --------------------------------------------------------------------------
# /sendotp/{service}
# --------------------------------------------------------------------------
@app.api_route(
    "/sendotp/{service}",
    methods=["GET", "POST"],
    dependencies=[Depends(require_key)],
    summary="Record an incoming OTP / SMS for a service",
)
def send_otp(
    service: str,
    number: str = Query(..., description="Phone number that received the SMS"),
    sms: str = Query(..., description="Full text of the SMS"),
):
    clean = _clean_number(number)
    if len(re.sub(r"\D", "", clean)) < 5:
        raise HTTPException(status_code=422, detail="Invalid 'number'")

    record = {
        "id": next(_next_id),
        "service": service.strip().lower(),
        "number": clean,
        "sms": sms,
        "otp": _extract_otp(sms),
        "received_at": _now(),
    }

    with _lock:
        _messages.append(record)
        if len(_messages) > MAX_STORED:
            del _messages[:-MAX_STORED]

    return {"ok": True, "message": record}


# --------------------------------------------------------------------------
# /poll
# --------------------------------------------------------------------------
@app.get(
    "/poll",
    dependencies=[Depends(require_key)],
    summary="Read every OTP that has been sent",
)
def poll(
    service: Optional[str] = Query(None, description="Filter by service name"),
    number: Optional[str] = Query(None, description="Filter by phone number"),
    since_id: int = Query(0, ge=0, description="Only return messages with id > since_id"),
    limit: int = Query(100, ge=1, le=500, description="Max messages to return"),
):
    with _lock:
        snapshot = list(_messages)
        latest_id = _messages[-1]["id"] if _messages else 0

    if service:
        want = service.strip().lower()
        snapshot = [m for m in snapshot if m["service"] == want]

    if number:
        want_num = _clean_number(number)
        snapshot = [m for m in snapshot if m["number"] == want_num]

    if since_id:
        snapshot = [m for m in snapshot if m["id"] > since_id]

    snapshot = snapshot[-limit:]

    return {
        "count": len(snapshot),
        "latest_id": latest_id,
        "messages": snapshot,
    }


@app.delete(
    "/poll",
    dependencies=[Depends(require_key)],
    summary="Clear the inbox",
)
def clear_poll():
    with _lock:
        cleared = len(_messages)
        _messages.clear()
    return {"ok": True, "cleared": cleared}


# --------------------------------------------------------------------------
# /health
# --------------------------------------------------------------------------
@app.get("/health")
def health():
    with _lock:
        return {"ok": True, "stored": len(_messages)}


# --------------------------------------------------------------------------
# Local dev / Render entrypoint
# --------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
