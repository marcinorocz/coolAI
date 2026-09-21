"""Minimal durable audit records. Never store arguments, prompts or tokens."""

import sqlite3
import time
import uuid
from contextlib import closing
from pathlib import Path

from .approvals import private_database
from .engine import Evaluation, canonical


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        private_database(self.path)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, time REAL NOT NULL, record TEXT NOT NULL)"
            )

    def record(self, evaluation: Evaluation, phase: str, request_id: str, actor: str | None = None):
        data = evaluation.as_dict() | {"phase": phase, "request_id": request_id}
        if actor is not None:
            data["actor"] = actor
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute(
                "INSERT INTO events VALUES (?, ?, ?)", (uuid.uuid4().hex, time.time(), canonical(data))
            )
