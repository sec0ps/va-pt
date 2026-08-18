#!/usr/bin/env python3
# =============================================================================
# Location: store.py
#
# Author: Keith Pachulski
# Company: Red Cell Security LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2026 Keith Pachulski. All rights reserved.
#
# License: MIT License
#
#   Permission is hereby granted, free of charge, to any person obtaining a
#   copy of this software and associated documentation files (the "Software"),
#   to deal in the Software without restriction, including without limitation
#   the rights to use, copy, modify, merge, publish, distribute, sublicense,
#   and/or sell copies of the Software, and to permit persons to whom the
#   Software is furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#   DEALINGS IN THE SOFTWARE.
#
# Purpose:
#   Persists engagement sessions and operator saved markers to SQLite.
#
#   One engagement is one session row, and every marker is bound to a session.
#   Markers are never shared across sessions, which keeps observations from one
#   engagement out of the working set of another. The same constraint becomes the
#   tenant isolation boundary if this store is later moved to a server grade
#   database for multi node deployment.
#
#   A marker records the detected event rather than the pixel the operator
#   clicked. Center frequency, occupied bandwidth, level, floor, and the first and
#   last time the signal was seen are all measured values from the detector. The
#   antenna in use is recorded alongside them, because a level reading without the
#   antenna context is not interpretable weeks later when the capture is reviewed.
#
#   Write ahead logging is enabled so that a reader compiling a report does not
#   block the sweep thread writing new markers, and so that an ungraceful exit
#   mid engagement leaves a recoverable database rather than a truncated one.
#
# SECURITY NOTICE:
#   This module is part of an RF spectrum analysis platform intended for
#   authorized red team engagements and defensive spectrum monitoring conducted
#   within a documented scope of engagement. This store holds observation
#   metadata only. It does not store IQ, audio, or any demodulated communications
#   content. The database file is unencrypted, so it inherits the protection of
#   the filesystem it sits on and should be handled at the classification of the
#   engagement it documents.
#
# DISCLAIMER:
#   This software is provided for lawful, authorized use only. The author and Red
#   Cell Security LLC accept no liability for any use of this software, whether
#   authorized or otherwise.
# =============================================================================

"""SQLite persistence for engagement sessions and operator saved markers."""

import json
import os
import sqlite3
import threading
import time
from typing import Dict, List, Optional

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_info (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    preset_key  TEXT,
    band_plan   TEXT,
    gain        TEXT,
    started_at  REAL    NOT NULL,
    ended_at    REAL,
    ppm_correction REAL DEFAULT 0.0,
    notes       TEXT    DEFAULT ''
);

CREATE TABLE IF NOT EXISTS markers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER NOT NULL,
    label           TEXT    NOT NULL,
    center_hz       REAL    NOT NULL,
    occupied_bw_hz  REAL,
    peak_dbfs       REAL,
    floor_dbfs      REAL,
    snr_db          REAL,
    first_seen      REAL,
    last_seen       REAL,
    duration_s      REAL,
    frame_count     INTEGER,
    classification  TEXT,
    band_name       TEXT,
    antenna_note    TEXT    DEFAULT '',
    notes           TEXT    DEFAULT '',
    created_at      REAL    NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_markers_session ON markers(session_id);
CREATE INDEX IF NOT EXISTS idx_markers_center  ON markers(session_id, center_hz);
"""


class Store:
    """Thread safe SQLite store for sessions and markers.

    A single connection is shared behind a lock rather than opening one per
    thread. Marker writes are operator paced and rare compared to the sweep, so
    lock contention is not a concern, and a single connection avoids the write
    lock conflicts that several concurrent writers would otherwise hit.
    """

    def __init__(self, path: str = "spectrum.db"):
        self.path = path
        directory = os.path.dirname(os.path.abspath(path))
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)

        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._configure()
        self._migrate()
        self.session_id: Optional[int] = None

    def _configure(self) -> None:
        """Apply pragmas. WAL keeps readers from blocking the writing thread."""
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            # NORMAL rather than FULL. Under WAL this still survives an
            # application crash, only losing durability against an OS level
            # crash, and it avoids an fsync on every marker write.
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.commit()

    def _migrate(self) -> None:
        """Create the schema and record its version."""
        with self._lock:
            self._conn.executescript(SCHEMA)
            row = self._conn.execute("SELECT version FROM schema_info").fetchone()
            if row is None:
                self._conn.execute("INSERT INTO schema_info (version) VALUES (?)", (SCHEMA_VERSION,))
            self._conn.commit()

    def close(self) -> None:
        """Close the connection, ending any open session first."""
        if self.session_id is not None:
            self.end_session()
        with self._lock:
            self._conn.close()

    def start_session(
        self,
        name: str,
        preset_key: Optional[str] = None,
        band_plan: Optional[List[Dict]] = None,
        gain: Optional[Dict] = None,
        notes: str = "",
    ) -> int:
        """Open a new session and make it the active one for marker writes."""
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO sessions (name, preset_key, band_plan, gain, started_at, notes) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    name,
                    preset_key,
                    json.dumps(band_plan) if band_plan else None,
                    json.dumps(gain) if gain else None,
                    time.time(),
                    notes,
                ),
            )
            self._conn.commit()
            self.session_id = int(cursor.lastrowid)
        return self.session_id

    def end_session(self) -> None:
        """Stamp the active session closed."""
        if self.session_id is None:
            return
        with self._lock:
            self._conn.execute(
                "UPDATE sessions SET ended_at = ? WHERE id = ?",
                (time.time(), self.session_id),
            )
            self._conn.commit()
        self.session_id = None

    def set_ppm_correction(self, ppm: float) -> None:
        """Record the frequency correction derived for this session.

        The HackRF crystal is not temperature compensated and drifts most during
        the first minutes after power on. Storing the correction with the session
        rather than globally means markers taken in one session can be reconciled
        later without assuming the same offset applied to another.
        """
        if self.session_id is None:
            return
        with self._lock:
            self._conn.execute(
                "UPDATE sessions SET ppm_correction = ? WHERE id = ?",
                (float(ppm), self.session_id),
            )
            self._conn.commit()

    def save_marker(self, label: str, event: Dict, notes: str = "") -> int:
        """Persist a marker from a detector event dict.

        The event dict is the detector's own measurement of the signal. Nothing
        here is derived from cursor position, so a marker saved from a click at
        the edge of a signal still records the measured center frequency rather
        than wherever the pointer happened to land.
        """
        if self.session_id is None:
            raise RuntimeError("no active session, call start_session first")

        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO markers ("
                "session_id, label, center_hz, occupied_bw_hz, peak_dbfs, floor_dbfs, "
                "snr_db, first_seen, last_seen, duration_s, frame_count, classification, "
                "band_name, antenna_note, notes, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    self.session_id,
                    label,
                    float(event.get("center_hz", 0.0)),
                    event.get("occupied_bw_hz"),
                    event.get("peak_dbfs"),
                    event.get("floor_dbfs"),
                    event.get("snr_db"),
                    event.get("first_seen"),
                    event.get("last_seen"),
                    event.get("duration_s"),
                    event.get("frame_count"),
                    event.get("classification"),
                    event.get("band_name"),
                    event.get("antenna_note", ""),
                    notes,
                    time.time(),
                ),
            )
            self._conn.commit()
            return int(cursor.lastrowid)

    def update_marker(self, marker_id: int, label: str, notes: str) -> None:
        """Edit the operator supplied fields of a marker, leaving measurements alone."""
        with self._lock:
            self._conn.execute(
                "UPDATE markers SET label = ?, notes = ? WHERE id = ?",
                (label, notes, int(marker_id)),
            )
            self._conn.commit()

    def delete_marker(self, marker_id: int) -> None:
        """Remove a marker."""
        with self._lock:
            self._conn.execute("DELETE FROM markers WHERE id = ?", (int(marker_id),))
            self._conn.commit()

    def list_markers(self, session_id: Optional[int] = None) -> List[Dict]:
        """All markers for a session, ordered by frequency for report use."""
        target = session_id if session_id is not None else self.session_id
        if target is None:
            return []
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM markers WHERE session_id = ? ORDER BY center_hz ASC",
                (int(target),),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_sessions(self) -> List[Dict]:
        """Every session with its marker count, newest first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT s.*, COUNT(m.id) AS marker_count "
                "FROM sessions s LEFT JOIN markers m ON m.session_id = s.id "
                "GROUP BY s.id ORDER BY s.started_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def export_session_csv(self, path: str, session_id: Optional[int] = None) -> int:
        """Write markers to CSV for inclusion in an engagement report."""
        import csv

        markers = self.list_markers(session_id)
        if not markers:
            return 0

        columns = [
            "center_hz", "occupied_bw_hz", "label", "classification", "band_name",
            "peak_dbfs", "floor_dbfs", "snr_db", "duration_s", "frame_count",
            "first_seen", "last_seen", "antenna_note", "notes",
        ]
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for marker in markers:
                writer.writerow(marker)
        return len(markers)
