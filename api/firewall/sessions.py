"""In-memory multi-turn session store with TTL."""
import os
import time

_TTL_SECONDS = 1800  # 30 min
_MAX_MESSAGES = 50

_store: dict[str, dict] = {}


def _is_enabled() -> bool:
    return os.environ.get("ENABLE_MULTI_TURN", "true").lower() == "true"


def add_message(session_id: str, role: str, text: str, verdict: str | None = None):
    if not _is_enabled() or not session_id:
        return
    if session_id not in _store:
        _store[session_id] = {"messages": [], "last_active": time.time()}
    session = _store[session_id]
    session["messages"].append({"role": role, "text": text, "verdict": verdict})
    session["messages"] = session["messages"][-_MAX_MESSAGES:]
    session["last_active"] = time.time()


def get_history(session_id: str) -> list[dict]:
    if not _is_enabled() or not session_id or session_id not in _store:
        return []
    return _store[session_id]["messages"]


def message_count(session_id: str) -> int:
    return len(get_history(session_id))


def prune():
    now = time.time()
    expired = [k for k, v in _store.items() if now - v["last_active"] > _TTL_SECONDS]
    for k in expired:
        del _store[k]
