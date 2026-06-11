"""Append-only audit log with a SHA-256 hash chain.

Every Guard tool call and every human decision is recorded. Each entry
includes the hash of the previous entry, so tampering with history is
detectable with verify_chain().
"""
import hashlib
import json
import time
from pathlib import Path

LOG_DIR = Path.home() / ".supertanks-guard"
GENESIS = "0" * 64


def _log_path(path: Path | None = None) -> Path:
    log_dir = path or LOG_DIR
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / "audit.jsonl"


def _last_hash(log_file: Path) -> str:
    if not log_file.exists():
        return GENESIS
    last = None
    with log_file.open() as f:
        for line in f:
            if line.strip():
                last = line
    if last is None:
        return GENESIS
    return json.loads(last)["hash"]


def record(event: str, detail: dict, path: Path | None = None) -> dict:
    log_file = _log_path(path)
    entry = {
        "ts": time.time(),
        "event": event,
        "detail": detail,
        "prev_hash": _last_hash(log_file),
    }
    payload = json.dumps(entry, sort_keys=True, ensure_ascii=False)
    entry["hash"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    with log_file.open("a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def tail(limit: int = 20, path: Path | None = None) -> list[dict]:
    log_file = _log_path(path)
    if not log_file.exists():
        return []
    lines = [l for l in log_file.read_text().splitlines() if l.strip()]
    return [json.loads(l) for l in lines[-limit:]]


def verify_chain(path: Path | None = None) -> dict:
    """Walk the full chain; report the first broken link, if any."""
    log_file = _log_path(path)
    if not log_file.exists():
        return {"ok": True, "entries": 0}
    prev = GENESIS
    n = 0
    for line in log_file.read_text().splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        claimed = entry.pop("hash")
        payload = json.dumps(entry, sort_keys=True, ensure_ascii=False)
        if entry["prev_hash"] != prev or hashlib.sha256(payload.encode()).hexdigest() != claimed:
            return {"ok": False, "entries": n, "broken_at": n + 1}
        prev = claimed
        n += 1
    return {"ok": True, "entries": n}
