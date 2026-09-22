"""HMAC approvals with persistent, atomic single-use consumption."""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
import time
from contextlib import closing
from pathlib import Path

from .engine import ValidationError, canonical


class ApprovalError(ValueError):
    pass


def private_database(path: Path) -> None:
    # Deploy in an operator-owned directory, inaccessible to the agent.
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValidationError("State must be stored in a regular file.")
        if os.name == "posix" and info.st_mode & 0o077:
            raise ValidationError("State files must be accessible only to their owner (chmod 600).")
    finally:
        os.close(fd)


class ApprovalStore:
    def __init__(self, path: Path, key: bytes, clock=time.time):
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValidationError("Approval key must contain at least 32 random bytes.")
        self.path, self.key, self.clock = Path(path), key, clock
        private_database(self.path)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS approvals (nonce TEXT PRIMARY KEY, token_hash TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0)"
            )

    def issue(self, action_id: str, policy_id: str, actor: str, ttl: int = 300) -> str:
        """Trusted operator API. Never expose this method to an agent as a tool."""
        if not isinstance(actor, str) or not actor.strip() or len(actor) > 120:
            raise ValidationError("An operator identity is required.")
        if type(ttl) is not int or not 1 <= ttl <= 3600:
            raise ValidationError("Approval TTL must be between 1 and 3600 seconds.")
        now = self.clock()
        payload = canonical(
            {
                "v": 1,
                "nonce": secrets.token_hex(16),
                "action_id": action_id,
                "policy_id": policy_id,
                "actor": actor,
                "issued_at": now,
                "expires_at": now + ttl,
            }
        )
        signature = hmac.new(self.key, payload.encode(), hashlib.sha256).hexdigest()
        token = payload.encode().hex() + "." + signature
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute(
                "INSERT INTO approvals(nonce, token_hash) VALUES (?, ?)",
                (json.loads(payload)["nonce"], hashlib.sha256(token.encode()).hexdigest()),
            )
        return token

    def consume(self, token: str, action_id: str, policy_id: str) -> str:
        try:
            if not isinstance(token, str) or len(token) > 8192:
                raise ValueError
            encoded, signature = token.split(".")
            payload = bytes.fromhex(encoded)
            expected = hmac.new(self.key, payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError
            data = json.loads(payload)
            now = self.clock()
            if (
                data["v"] != 1
                or data["action_id"] != action_id
                or data["policy_id"] != policy_id
                or not data["issued_at"] <= now < data["expires_at"]
            ):
                raise ValueError
            with closing(sqlite3.connect(self.path)) as db, db:
                changed = db.execute(
                    "UPDATE approvals SET used=1 WHERE nonce=? AND token_hash=? AND used=0",
                    (data["nonce"], hashlib.sha256(token.encode()).hexdigest()),
                ).rowcount
                if changed != 1:
                    raise ValueError
            return data["actor"]
        except (ValueError, KeyError, TypeError, UnicodeError) as exc:
            raise ApprovalError("Approval is invalid, expired, changed or already used.") from exc
