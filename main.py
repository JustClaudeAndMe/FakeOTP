"""
OTP Relay API
-------------
GET/POST  /sendotp/{service}?number=...&sms=...
GET       /poll                              -> all messages, immediate
GET       /poll?num=+XXXXXXXXXXX             -> long-poll for that number
DELETE    /poll
GET       /health
"""

import asyncio
import itertools
import os
import re
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

# --------------------------------------------------------------------------
# Optional API key. Set the API_KEY env var to lock the whole thing down.
# --------------------------------------------------------------------------
API_KEY = os.getenv("API_KEY")


def require_key(x_api_key: Optional[str] = Header(default=None)):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")


app = FastAPI(title="OTP Relay API", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------------------------------------
# In-memory store (single process, single event loop)
# --------------------------------------------------------------------------
_messages: list[dict] = []
_next_id = itertools.count(1)
MAX_STORED = 500

# number -> list of asyncio.Event, one per waiting /poll request
_waiters: dict[str, list[asyncio.Event]] = {}

OTP_RE = re.compile(r"\b\d{4,8}\b")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean_number(raw: str) -> str:
    """
    Normalize a phone number.
    In a query string `+` decodes to a space, so we fix that here.
    """
    n = re.sub(r"[\s\-().]", "", raw or "")
    if n and not n.startswith("+"):
        n = "+" + n
    return n


def _extract_otp(sms: str) -> Optional[str]:
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
            "poll_all": "GET /poll",
            "poll_wait": "GET /poll?num=+XXXXXXXXXXX",
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
async def send_otp(
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

    _messages.append(record)
    if len(_messages) > MAX_STORED:
        del _messages[:-MAX_STORED]

    # Wake up every long-polling /poll request waiting for this number
    for ev in _waiters.get(clean, []):
        ev.set()

    return {"ok": True, "message": record}


# --------------------------------------------------------------------------
# /poll
# --------------------------------------------------------------------------
@app.get(
    "/poll",
    dependencies=[Depends(require_key)],
    summary="Read OTPs. With ?num=... it long-polls until a new SMS arrives.",
)
async def poll(
    service: Optional[str] = Query(None, description="Filter by service name"),
    num: Optional[str] = Query(
        None,
        description="Phone number to long-poll for. Blocks until a new SMS arrives (or timeout).",
    ),
    number: Optional[str] = Query(None, description="Alias for 'num'"),
    since_id: int = Query(
        0, ge=0, description="Only return messages with id > since_id"
    ),
    limit: int = Query(100, ge=1, le=500, description="Max messages to return"),
    timeout: float = Query(
        30.0,
        ge=0,
        le=300,
        description="Max seconds to wait when num/number is set. 0 = return immediately.",
    ),
):
    target_raw = num or number
    target = _clean_number(target_raw) if target_raw else None

    def snapshot() -> list[dict]:
        msgs = _messages
        if service:
            want = service.strip().lower()
            msgs = [m for m in msgs if m["service"] == want]
        if target:
            msgs = [m for m in msgs if m["number"] == target]
        if since_id:
            msgs = [m for m in msgs if m["id"] > since_id]
        return msgs[-limit:]

    # No specific number -> return everything right away
    if not target:
        msgs = snapshot()
        latest_id = _messages[-1]["id"] if _messages else 0
        return {"count": len(msgs), "latest_id": latest_id, "messages": msgs}

    # Specific number -> long-poll until a new message arrives (or timeout)
    existing = snapshot()
    if existing or timeout == 0:
        latest_id = _messages[-1]["id"] if _messages else 0
        return {
            "count": len(existing),
            "latest_id": latest_id,
            "messages": existing,
            "waited": False,
        }

    ev = asyncio.Event()
    _waiters.setdefault(target, []).append(ev)
    try:
        try:
            await asyncio.wait_for(ev.wait(), timeout=timeout)
            waited = True
        except asyncio.TimeoutError:
            waited = False

        msgs = snapshot()
        latest_id = _messages[-1]["id"] if _messages else 0
        return {
            "count": len(msgs),
            "latest_id": latest_id,
            "messages": msgs,
            "waited": waited,
        }
    finally:
        lst = _waiters.get(target)
        if lst and ev in lst:
            lst.remove(ev)
        if lst is not None and not lst:
            _waiters.pop(target, None)


@app.delete(
    "/poll",
    dependencies=[Depends(require_key)],
    summary="Clear the inbox",
)
async def clear_poll():
    cleared = len(_messages)
    _messages.clear()
    return {"ok": True, "cleared": cleared}


@app.get("/health")
async def health():
    return {
        "ok": True,
        "stored": len(_messages),
        "waiters": sum(len(v) for v in _waiters.values()),
    }


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
