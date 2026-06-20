"""Persistence for recorded tool calls: SQLite (queryable) + JSONL (portable).

Every ``TraceEvent`` is written to both a SQLite table and an append-only
``traces/session-*.jsonl`` file. Inference reads the JSONL; the report queries
SQLite. Args/results are redacted by the caller before they reach here.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from agentperms.config import DB_FILE, TRACE_DIR
from agentperms.models import TraceEvent


class TraceStore:
    def __init__(self, db_path: str | Path = DB_FILE, trace_dir: str | Path = TRACE_DIR):
        self.db_path = Path(db_path)
        self.trace_dir = Path(trace_dir)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.trace_dir.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS trace_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                server TEXT NOT NULL,
                tool TEXT NOT NULL,
                args TEXT NOT NULL,
                result_summary TEXT,
                decision TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def _jsonl_path(self, session: str) -> Path:
        return self.trace_dir / f"session-{session}.jsonl"

    def record(self, event: TraceEvent, session: str = "default") -> None:
        self._conn.execute(
            "INSERT INTO trace_events (ts, server, tool, args, result_summary, decision)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                event.ts,
                event.server,
                event.tool,
                json.dumps(event.args),
                event.result_summary,
                event.decision.value,
            ),
        )
        self._conn.commit()
        with self._jsonl_path(session).open("a") as fh:
            fh.write(event.model_dump_json() + "\n")

    def all_events(self) -> list[TraceEvent]:
        rows = self._conn.execute(
            "SELECT ts, server, tool, args, result_summary, decision FROM trace_events ORDER BY ts"
        ).fetchall()
        return [
            TraceEvent(
                ts=r[0],
                server=r[1],
                tool=r[2],
                args=json.loads(r[3]),
                result_summary=r[4] or "",
                decision=r[5],
            )
            for r in rows
        ]

    def close(self) -> None:
        self._conn.close()


def load_jsonl(paths: list[str | Path]) -> list[TraceEvent]:
    """Load trace events from one or more JSONL files (used by `infer`)."""
    events: list[TraceEvent] = []
    for p in paths:
        path = Path(p)
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            events.append(TraceEvent.model_validate_json(line))
    return events
