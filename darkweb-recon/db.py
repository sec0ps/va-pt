# =============================================================================
# VAPT Toolkit - Vulnerability Assessment and Penetration Testing Toolkit
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2026 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: SQLite persistence layer for the darkweb recon subsystem. Creates the schema in WAL mode, seeds the built-in search sources, and provides the data-access functions for users, workspaces, watch terms, sources, jobs, schedules, findings, and matches.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#             In no event shall the authors or copyright holders be liable for any claim,
#             damages, or other liability, whether in an action of contract, tort, or otherwise,
#             arising from, out of, or in connection with the software or the use or other dealings
#             in the software.
#
# NOTICE: This toolkit is intended for authorized security testing only.
#         Users are responsible for ensuring compliance with all applicable laws
#         and regulations. Unauthorized use of these tools may violate local,
#         state, federal, and international laws.
#
# =============================================================================
# Location: darkweb-recon/db.py

"""SQLite schema and data-access layer for the darkweb recon service."""

import json
import hashlib
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from config import Config

_config = Config()


def _now():
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def connection():
    conn = sqlite3.connect(_config.db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _rows(cursor):
    return [dict(row) for row in cursor.fetchall()]


def _row(cursor):
    row = cursor.fetchone()
    return dict(row) if row is not None else None


SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS workspaces (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        client TEXT,
        created_at TEXT NOT NULL,
        created_by INTEGER
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS user_workspaces (
        user_id INTEGER NOT NULL,
        workspace_id INTEGER NOT NULL,
        PRIMARY KEY (user_id, workspace_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        kind TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        config_json TEXT,
        auth_blob TEXT,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS watch_terms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        workspace_id INTEGER NOT NULL,
        term TEXT NOT NULL,
        term_type TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        workspace_id INTEGER NOT NULL,
        status TEXT NOT NULL,
        trigger TEXT NOT NULL,
        source_subset TEXT,
        created_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT,
        error TEXT,
        stats_json TEXT,
        created_by INTEGER,
        FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS schedules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        workspace_id INTEGER NOT NULL,
        name TEXT,
        kind TEXT NOT NULL,
        interval_seconds INTEGER,
        cron TEXT,
        source_subset TEXT,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        created_by INTEGER,
        last_run_at TEXT,
        FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        workspace_id INTEGER NOT NULL,
        job_id INTEGER,
        source TEXT NOT NULL,
        url TEXT NOT NULL,
        title TEXT,
        snippet TEXT,
        content_hash TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'new',
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        UNIQUE (workspace_id, content_hash),
        FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS finding_matches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER NOT NULL,
        term_id INTEGER,
        term_type TEXT,
        matched_value TEXT,
        created_at TEXT NOT NULL,
        UNIQUE (finding_id, term_id, matched_value),
        FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS finding_sources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER NOT NULL,
        source TEXT NOT NULL,
        query TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        UNIQUE (finding_id, source),
        FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_findings_ws_status ON findings(workspace_id, status)",
    "CREATE INDEX IF NOT EXISTS idx_terms_ws ON watch_terms(workspace_id)",
    "CREATE INDEX IF NOT EXISTS idx_jobs_ws ON jobs(workspace_id)",
    """
    CREATE TABLE IF NOT EXISTS analyses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER NOT NULL,
        workspace_id INTEGER NOT NULL,
        status TEXT NOT NULL,
        root_url TEXT NOT NULL,
        created_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT,
        error TEXT,
        stats_json TEXT,
        created_by INTEGER,
        FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS analysis_pages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id INTEGER NOT NULL,
        url TEXT NOT NULL,
        title TEXT,
        text TEXT,
        links_json TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_analyses_finding ON analyses(finding_id)",
    "CREATE INDEX IF NOT EXISTS idx_analysis_pages_analysis ON analysis_pages(analysis_id)",
    """
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
]


def init_db():
    _config.ensure_dirs()
    with connection() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        for statement in SCHEMA:
            conn.execute(statement)
        cur = conn.execute("SELECT id FROM sources WHERE name = ?", ("ahmia",))
        if cur.fetchone() is None:
            conn.execute(
                "INSERT INTO sources (name, kind, enabled, config_json, auth_blob, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("ahmia", "search", 1, json.dumps({}), None, _now()),
            )
        cur = conn.execute("SELECT id FROM sources WHERE name = ?", ("torch",))
        if cur.fetchone() is None:
            conn.execute(
                "INSERT INTO sources (name, kind, enabled, config_json, auth_blob, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("torch", "search", 1, json.dumps({}), None, _now()),
            )
        cur = conn.execute("SELECT id FROM sources WHERE name = ?", ("excavator",))
        if cur.fetchone() is None:
            conn.execute(
                "INSERT INTO sources (name, kind, enabled, config_json, auth_blob, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("excavator", "search", 1, json.dumps({}), None, _now()),
            )
        cur = conn.execute("SELECT id FROM sources WHERE name = ?", ("tor66",))
        if cur.fetchone() is None:
            conn.execute(
                "INSERT INTO sources (name, kind, enabled, config_json, auth_blob, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("tor66", "search", 1, json.dumps({}), None, _now()),
            )


# users

def create_user(username, password_hash, role):
    with connection() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role, active, created_at) "
            "VALUES (?, ?, ?, 1, ?)",
            (username, password_hash, role, _now()),
        )
        return cur.lastrowid


def get_user_by_username(username):
    with connection() as conn:
        return _row(conn.execute("SELECT * FROM users WHERE username = ?", (username,)))


def get_user(user_id):
    with connection() as conn:
        return _row(conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)))


def list_users():
    with connection() as conn:
        return _rows(conn.execute("SELECT * FROM users ORDER BY username"))


def count_users():
    with connection() as conn:
        return conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]


def set_user_active(user_id, active):
    with connection() as conn:
        conn.execute("UPDATE users SET active = ? WHERE id = ?", (1 if active else 0, user_id))


# workspaces

def create_workspace(name, client, created_by):
    with connection() as conn:
        cur = conn.execute(
            "INSERT INTO workspaces (name, client, created_at, created_by) VALUES (?, ?, ?, ?)",
            (name, client, _now(), created_by),
        )
        return cur.lastrowid


def get_workspace(workspace_id):
    with connection() as conn:
        return _row(conn.execute("SELECT * FROM workspaces WHERE id = ?", (workspace_id,)))


def delete_workspace(workspace_id):
    # ON DELETE CASCADE removes the workspace's watch terms, schedules, jobs, and
    # findings (and, in turn, finding_matches, finding_sources, and analyses).
    with connection() as conn:
        conn.execute("DELETE FROM workspaces WHERE id = ?", (workspace_id,))


def get_workspace_by_name(name):
    with connection() as conn:
        return _row(conn.execute("SELECT * FROM workspaces WHERE name = ?", (name,)))


def list_workspaces():
    with connection() as conn:
        return _rows(conn.execute("SELECT * FROM workspaces ORDER BY name"))


def list_workspaces_for_user(user_id):
    with connection() as conn:
        return _rows(conn.execute(
            "SELECT w.* FROM workspaces w "
            "JOIN user_workspaces uw ON uw.workspace_id = w.id "
            "WHERE uw.user_id = ? ORDER BY w.name",
            (user_id,),
        ))


def add_membership(user_id, workspace_id):
    with connection() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO user_workspaces (user_id, workspace_id) VALUES (?, ?)",
            (user_id, workspace_id),
        )


def remove_membership(user_id, workspace_id):
    with connection() as conn:
        conn.execute(
            "DELETE FROM user_workspaces WHERE user_id = ? AND workspace_id = ?",
            (user_id, workspace_id),
        )


def user_has_workspace(user_id, workspace_id):
    with connection() as conn:
        row = conn.execute(
            "SELECT 1 FROM user_workspaces WHERE user_id = ? AND workspace_id = ?",
            (user_id, workspace_id),
        ).fetchone()
        return row is not None


def list_memberships(workspace_id):
    with connection() as conn:
        return _rows(conn.execute(
            "SELECT u.id, u.username, u.role FROM users u "
            "JOIN user_workspaces uw ON uw.user_id = u.id "
            "WHERE uw.workspace_id = ? ORDER BY u.username",
            (workspace_id,),
        ))


# sources

def list_sources():
    with connection() as conn:
        return _rows(conn.execute("SELECT * FROM sources ORDER BY name"))


def list_enabled_sources():
    with connection() as conn:
        return _rows(conn.execute("SELECT * FROM sources WHERE enabled = 1 ORDER BY name"))


def get_source(source_id):
    with connection() as conn:
        return _row(conn.execute("SELECT * FROM sources WHERE id = ?", (source_id,)))


def set_source_enabled(source_id, enabled):
    with connection() as conn:
        conn.execute("UPDATE sources SET enabled = ? WHERE id = ?", (1 if enabled else 0, source_id))


def update_source_config(source_id, config_dict):
    with connection() as conn:
        conn.execute(
            "UPDATE sources SET config_json = ? WHERE id = ?",
            (json.dumps(config_dict), source_id),
        )


# watch terms

def create_watch_term(workspace_id, term, term_type):
    with connection() as conn:
        cur = conn.execute(
            "INSERT INTO watch_terms (workspace_id, term, term_type, enabled, created_at) "
            "VALUES (?, ?, ?, 1, ?)",
            (workspace_id, term, term_type, _now()),
        )
        return cur.lastrowid


def list_watch_terms(workspace_id):
    with connection() as conn:
        return _rows(conn.execute(
            "SELECT * FROM watch_terms WHERE workspace_id = ? ORDER BY id", (workspace_id,)))


def get_watch_term(term_id):
    with connection() as conn:
        return _row(conn.execute("SELECT * FROM watch_terms WHERE id = ?", (term_id,)))


def list_enabled_watch_terms(workspace_id):
    with connection() as conn:
        return _rows(conn.execute(
            "SELECT * FROM watch_terms WHERE workspace_id = ? AND enabled = 1 ORDER BY id",
            (workspace_id,)))


def set_watch_term_enabled(term_id, enabled):
    with connection() as conn:
        conn.execute(
            "UPDATE watch_terms SET enabled = ? WHERE id = ?", (1 if enabled else 0, term_id))


def delete_watch_term(term_id):
    with connection() as conn:
        conn.execute("DELETE FROM watch_terms WHERE id = ?", (term_id,))


# jobs

def create_job(workspace_id, trigger, source_subset, created_by):
    subset = json.dumps(source_subset) if source_subset else None
    with connection() as conn:
        cur = conn.execute(
            "INSERT INTO jobs (workspace_id, status, trigger, source_subset, created_at, created_by) "
            "VALUES (?, 'queued', ?, ?, ?, ?)",
            (workspace_id, trigger, subset, _now(), created_by),
        )
        return cur.lastrowid


def mark_job_running(job_id):
    with connection() as conn:
        conn.execute(
            "UPDATE jobs SET status = 'running', started_at = ? WHERE id = ?", (_now(), job_id))


def mark_job_finished(job_id, status, stats, error):
    with connection() as conn:
        conn.execute(
            "UPDATE jobs SET status = ?, finished_at = ?, stats_json = ?, error = ? WHERE id = ?",
            (status, _now(), json.dumps(stats) if stats else None, error, job_id),
        )


def get_job(job_id):
    with connection() as conn:
        return _row(conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)))


def list_jobs(workspace_id, limit=25):
    with connection() as conn:
        return _rows(conn.execute(
            "SELECT * FROM jobs WHERE workspace_id = ? ORDER BY id DESC LIMIT ?",
            (workspace_id, limit)))


def list_recent_jobs(limit=25):
    with connection() as conn:
        return _rows(conn.execute(
            "SELECT j.*, w.name AS workspace_name FROM jobs j "
            "JOIN workspaces w ON w.id = j.workspace_id ORDER BY j.id DESC LIMIT ?", (limit,)))


def _placeholders(values):
    return ",".join("?" * len(values))


def count_running():
    with connection() as conn:
        jobs = conn.execute("SELECT COUNT(*) AS c FROM jobs WHERE status = 'running'").fetchone()["c"]
        analyses = conn.execute(
            "SELECT COUNT(*) AS c FROM analyses WHERE status = 'running'").fetchone()["c"]
        return jobs + analyses


def list_recent_jobs_for_workspaces(workspace_ids, limit=15):
    if not workspace_ids:
        return []
    query = (
        "SELECT j.*, w.name AS workspace_name FROM jobs j "
        "JOIN workspaces w ON w.id = j.workspace_id "
        "WHERE j.workspace_id IN (%s) ORDER BY j.id DESC LIMIT ?" % _placeholders(workspace_ids))
    with connection() as conn:
        return _rows(conn.execute(query, list(workspace_ids) + [limit]))


def findings_status_counts(workspace_ids):
    if not workspace_ids:
        return {}
    query = ("SELECT status, COUNT(*) AS c FROM findings WHERE workspace_id IN (%s) "
             "GROUP BY status" % _placeholders(workspace_ids))
    with connection() as conn:
        return {r["status"]: r["c"] for r in _rows(conn.execute(query, list(workspace_ids)))}


def findings_source_counts(workspace_ids):
    if not workspace_ids:
        return []
    query = ("SELECT source, COUNT(*) AS c FROM findings WHERE workspace_id IN (%s) "
             "GROUP BY source ORDER BY c DESC" % _placeholders(workspace_ids))
    with connection() as conn:
        return _rows(conn.execute(query, list(workspace_ids)))


def jobs_per_day(workspace_ids, days=7):
    if not workspace_ids:
        return []
    query = ("SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS c FROM jobs "
             "WHERE workspace_id IN (%s) GROUP BY day ORDER BY day DESC LIMIT ?"
             % _placeholders(workspace_ids))
    with connection() as conn:
        return _rows(conn.execute(query, list(workspace_ids) + [days]))


# schedules

def create_schedule(workspace_id, name, kind, interval_seconds, cron, source_subset, created_by):
    subset = json.dumps(source_subset) if source_subset else None
    with connection() as conn:
        cur = conn.execute(
            "INSERT INTO schedules (workspace_id, name, kind, interval_seconds, cron, "
            "source_subset, enabled, created_at, created_by) "
            "VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)",
            (workspace_id, name, kind, interval_seconds, cron, subset, _now(), created_by),
        )
        return cur.lastrowid


def get_schedule(schedule_id):
    with connection() as conn:
        return _row(conn.execute("SELECT * FROM schedules WHERE id = ?", (schedule_id,)))


def list_schedules(workspace_id):
    with connection() as conn:
        return _rows(conn.execute(
            "SELECT * FROM schedules WHERE workspace_id = ? ORDER BY id", (workspace_id,)))


def list_enabled_schedules():
    with connection() as conn:
        return _rows(conn.execute("SELECT * FROM schedules WHERE enabled = 1 ORDER BY id"))


def set_schedule_enabled(schedule_id, enabled):
    with connection() as conn:
        conn.execute(
            "UPDATE schedules SET enabled = ? WHERE id = ?", (1 if enabled else 0, schedule_id))


def delete_schedule(schedule_id):
    with connection() as conn:
        conn.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))


def mark_schedule_run(schedule_id):
    with connection() as conn:
        conn.execute(
            "UPDATE schedules SET last_run_at = ? WHERE id = ?", (_now(), schedule_id))


# findings

def _normalize_url(url):
    # Collapse cosmetic differences so the same onion result dedups across engines:
    # drop scheme, lowercase, strip a trailing slash. Distinct paths stay distinct.
    u = (url or "").strip().lower()
    for scheme in ("http://", "https://"):
        if u.startswith(scheme):
            u = u[len(scheme):]
            break
    return u.rstrip("/")


def _finding_key(url):
    return hashlib.sha256(_normalize_url(url).encode("utf-8", "replace")).hexdigest()


def upsert_finding(workspace_id, job_id, hit, snippet_max):
    snippet = (hit["snippet"] or "")[:snippet_max]
    key = _finding_key(hit["url"])
    now = _now()
    with connection() as conn:
        existing = conn.execute(
            "SELECT id FROM findings WHERE workspace_id = ? AND content_hash = ?",
            (workspace_id, key),
        ).fetchone()
        if existing is None:
            cur = conn.execute(
                "INSERT INTO findings (workspace_id, job_id, source, url, title, snippet, "
                "content_hash, status, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'new', ?, ?)",
                (workspace_id, job_id, hit["source"], hit["url"], hit["title"], snippet,
                 key, now, now),
            )
            return cur.lastrowid, True
        finding_id = existing["id"]
        conn.execute(
            "UPDATE findings SET last_seen = ?, job_id = ? WHERE id = ?",
            (now, job_id, finding_id),
        )
        return finding_id, False


def record_finding_source(finding_id, source, query):
    # Provenance: which engine surfaced this finding, and via which query. One row
    # per engine; repeat sightings refresh last_seen. This is not a content match.
    now = _now()
    with connection() as conn:
        conn.execute(
            "INSERT INTO finding_sources (finding_id, source, query, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(finding_id, source) DO UPDATE SET last_seen = excluded.last_seen",
            (finding_id, source, (query or "")[:200], now, now),
        )


def list_finding_sources(finding_id):
    with connection() as conn:
        return _rows(conn.execute(
            "SELECT source, query, first_seen, last_seen FROM finding_sources "
            "WHERE finding_id = ? ORDER BY first_seen", (finding_id,)))


def finding_sources_map(finding_ids):
    # {finding_id: [source, ...]} for a set of findings, for the list-view badge.
    ids = list(finding_ids)
    if not ids:
        return {}
    placeholders = ",".join("?" * len(ids))
    out = {}
    with connection() as conn:
        rows = conn.execute(
            "SELECT finding_id, source FROM finding_sources "
            "WHERE finding_id IN (%s) ORDER BY source" % placeholders, ids).fetchall()
    for r in rows:
        out.setdefault(r["finding_id"], []).append(r["source"])
    return out


def add_finding_match(finding_id, term_id, term_type, matched_value):
    with connection() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO finding_matches (finding_id, term_id, term_type, "
            "matched_value, created_at) VALUES (?, ?, ?, ?, ?)",
            (finding_id, term_id, term_type, matched_value, _now()),
        )


def list_findings(workspace_id, status=None, limit=200, offset=0, matched=False):
    query = "SELECT * FROM findings WHERE workspace_id = ?"
    params = [workspace_id]
    if status:
        query += " AND status = ?"
        params.append(status)
    if matched:
        query += " AND EXISTS (SELECT 1 FROM finding_matches m WHERE m.finding_id = findings.id)"
    query += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
    params.append(limit)
    params.append(offset)
    with connection() as conn:
        return _rows(conn.execute(query, params))


def count_findings(workspace_id, status=None, matched=False):
    query = "SELECT COUNT(*) AS c FROM findings WHERE workspace_id = ?"
    params = [workspace_id]
    if status:
        query += " AND status = ?"
        params.append(status)
    if matched:
        query += " AND EXISTS (SELECT 1 FROM finding_matches m WHERE m.finding_id = findings.id)"
    with connection() as conn:
        return conn.execute(query, params).fetchone()["c"]


def get_finding(finding_id):
    with connection() as conn:
        return _row(conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)))


def list_matches_for_finding(finding_id):
    with connection() as conn:
        return _rows(conn.execute(
            "SELECT * FROM finding_matches WHERE finding_id = ? ORDER BY id", (finding_id,)))


def set_finding_status(finding_id, status):
    with connection() as conn:
        conn.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))


def count_findings_by_status(workspace_id):
    with connection() as conn:
        rows = _rows(conn.execute(
            "SELECT status, COUNT(*) AS c FROM findings WHERE workspace_id = ? GROUP BY status",
            (workspace_id,)))
        return {row["status"]: row["c"] for row in rows}


# analyses

def create_analysis(finding_id, workspace_id, root_url, created_by):
    with connection() as conn:
        cur = conn.execute(
            "INSERT INTO analyses (finding_id, workspace_id, status, root_url, created_at, created_by) "
            "VALUES (?, ?, 'queued', ?, ?, ?)",
            (finding_id, workspace_id, root_url, _now(), created_by),
        )
        return cur.lastrowid


def get_analysis(analysis_id):
    with connection() as conn:
        return _row(conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)))


def mark_analysis_running(analysis_id):
    with connection() as conn:
        conn.execute(
            "UPDATE analyses SET status = 'running', started_at = ? WHERE id = ?",
            (_now(), analysis_id))


def mark_analysis_finished(analysis_id, status, stats, error):
    with connection() as conn:
        conn.execute(
            "UPDATE analyses SET status = ?, finished_at = ?, stats_json = ?, error = ? WHERE id = ?",
            (status, _now(), json.dumps(stats) if stats else None, error, analysis_id),
        )


def add_analysis_page(analysis_id, url, title, text, links):
    with connection() as conn:
        conn.execute(
            "INSERT INTO analysis_pages (analysis_id, url, title, text, links_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (analysis_id, url, title, text, json.dumps(links), _now()),
        )


def list_analysis_pages(analysis_id):
    with connection() as conn:
        return _rows(conn.execute(
            "SELECT * FROM analysis_pages WHERE analysis_id = ? ORDER BY id", (analysis_id,)))


def list_analyses_for_finding(finding_id):
    with connection() as conn:
        return _rows(conn.execute(
            "SELECT * FROM analyses WHERE finding_id = ? ORDER BY id DESC", (finding_id,)))


# settings

def get_settings():
    with connection() as conn:
        return {row["key"]: row["value"]
                for row in _rows(conn.execute("SELECT key, value FROM settings"))}


def set_setting(key, value):
    with connection() as conn:
        conn.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (key, value, _now()),
        )


def delete_setting(key):
    with connection() as conn:
        conn.execute("DELETE FROM settings WHERE key = ?", (key,))
