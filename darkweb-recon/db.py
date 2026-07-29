"""SQLite schema and data-access layer for the darkweb recon service."""

import json
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
    "CREATE INDEX IF NOT EXISTS idx_findings_ws_status ON findings(workspace_id, status)",
    "CREATE INDEX IF NOT EXISTS idx_terms_ws ON watch_terms(workspace_id)",
    "CREATE INDEX IF NOT EXISTS idx_jobs_ws ON jobs(workspace_id)",
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

def upsert_finding(workspace_id, job_id, hit, snippet_max):
    snippet = (hit["snippet"] or "")[:snippet_max]
    now = _now()
    with connection() as conn:
        existing = conn.execute(
            "SELECT id FROM findings WHERE workspace_id = ? AND content_hash = ?",
            (workspace_id, hit["content_hash"]),
        ).fetchone()
        if existing is None:
            cur = conn.execute(
                "INSERT INTO findings (workspace_id, job_id, source, url, title, snippet, "
                "content_hash, status, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'new', ?, ?)",
                (workspace_id, job_id, hit["source"], hit["url"], hit["title"], snippet,
                 hit["content_hash"], now, now),
            )
            return cur.lastrowid, True
        finding_id = existing["id"]
        conn.execute(
            "UPDATE findings SET last_seen = ?, job_id = ? WHERE id = ?",
            (now, job_id, finding_id),
        )
        return finding_id, False


def add_finding_match(finding_id, term_id, term_type, matched_value):
    with connection() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO finding_matches (finding_id, term_id, term_type, "
            "matched_value, created_at) VALUES (?, ?, ?, ?, ?)",
            (finding_id, term_id, term_type, matched_value, _now()),
        )


def list_findings(workspace_id, status=None, limit=200, offset=0):
    query = "SELECT * FROM findings WHERE workspace_id = ?"
    params = [workspace_id]
    if status:
        query += " AND status = ?"
        params.append(status)
    query += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
    params.append(limit)
    params.append(offset)
    with connection() as conn:
        return _rows(conn.execute(query, params))


def count_findings(workspace_id, status=None):
    query = "SELECT COUNT(*) AS c FROM findings WHERE workspace_id = ?"
    params = [workspace_id]
    if status:
        query += " AND status = ?"
        params.append(status)
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
