"""Local GO-GATE: deny-by-default action gating with human approval and TTL.

Follows the GO-GATE semantics from super-tanks: an agent may *request* a
risky action, but nothing is allowed until a human explicitly approves it
out-of-band (CLI), and every approval expires.
"""
import sqlite3
import time
import uuid
from pathlib import Path

DEFAULT_TTL = 300  # seconds — approvals are short-lived by design
DB_DIR = Path.home() / ".supertanks-guard"


def _db(path: Path | None = None) -> sqlite3.Connection:
    db_dir = path or DB_DIR
    db_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_dir / "guard.db")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS transactions (
            tx_id TEXT PRIMARY KEY,
            action TEXT NOT NULL,
            params TEXT NOT NULL DEFAULT '',
            risk TEXT NOT NULL DEFAULT 'medium',
            status TEXT NOT NULL DEFAULT 'pending',
            created_at REAL NOT NULL,
            ttl INTEGER NOT NULL,
            decided_at REAL,
            decided_by TEXT
        )"""
    )
    return conn


def _expire(conn: sqlite3.Connection) -> None:
    """Lazily expire pending transactions past their TTL (fail-closed)."""
    now = time.time()
    conn.execute(
        "UPDATE transactions SET status='expired' "
        "WHERE status='pending' AND created_at + ttl < ?",
        (now,),
    )
    conn.commit()


def request_action(action: str, params: str = "", risk: str = "medium",
                   ttl: int = DEFAULT_TTL, db_path: Path | None = None) -> dict:
    """Register a pending transaction. Nothing is approved implicitly."""
    ttl = max(10, min(int(ttl), 3600))
    tx_id = uuid.uuid4().hex[:12]
    conn = _db(db_path)
    conn.execute(
        "INSERT INTO transactions (tx_id, action, params, risk, status, created_at, ttl) "
        "VALUES (?, ?, ?, ?, 'pending', ?, ?)",
        (tx_id, action, params, risk, time.time(), ttl),
    )
    conn.commit()
    conn.close()
    return {"tx_id": tx_id, "status": "pending", "ttl_seconds": ttl}


def status(tx_id: str, db_path: Path | None = None) -> dict:
    conn = _db(db_path)
    _expire(conn)
    row = conn.execute(
        "SELECT tx_id, action, risk, status, created_at, ttl, decided_by "
        "FROM transactions WHERE tx_id=?", (tx_id,)
    ).fetchone()
    conn.close()
    if row is None:
        # Unknown id is a denial, not an error — fail closed.
        return {"tx_id": tx_id, "status": "denied", "reason": "unknown transaction"}
    return {
        "tx_id": row[0], "action": row[1], "risk": row[2], "status": row[3],
        "expires_in": max(0, int(row[4] + row[5] - time.time())) if row[3] == "pending" else 0,
        "decided_by": row[6],
    }


def decide(tx_id: str, approve: bool, decided_by: str = "human_cli",
           db_path: Path | None = None) -> dict:
    """Human decision. Only pending (non-expired) transactions can be decided."""
    conn = _db(db_path)
    _expire(conn)
    new_status = "approved" if approve else "denied"
    cur = conn.execute(
        "UPDATE transactions SET status=?, decided_at=?, decided_by=? "
        "WHERE tx_id=? AND status='pending'",
        (new_status, time.time(), decided_by, tx_id),
    )
    conn.commit()
    changed = cur.rowcount == 1
    conn.close()
    if not changed:
        return {"tx_id": tx_id, "ok": False, "reason": "not pending (unknown, decided or expired)"}
    return {"tx_id": tx_id, "ok": True, "status": new_status}


def pending(db_path: Path | None = None) -> list[dict]:
    conn = _db(db_path)
    _expire(conn)
    rows = conn.execute(
        "SELECT tx_id, action, params, risk, created_at, ttl FROM transactions "
        "WHERE status='pending' ORDER BY created_at"
    ).fetchall()
    conn.close()
    now = time.time()
    return [
        {"tx_id": r[0], "action": r[1], "params": r[2], "risk": r[3],
         "expires_in": max(0, int(r[4] + r[5] - now))}
        for r in rows
    ]
