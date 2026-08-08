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
# Purpose: Flask console HTTP routes for the darkweb recon subsystem: authentication and session handling, workspace/finding/source/user/settings views, watch-term and schedule management, manual job and site-analysis triggers, and finding triage actions.
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
# Location: darkweb-recon/console/routes.py

"""All console HTTP routes."""

import json
import os

from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, abort, g, session, current_app)
from apscheduler.triggers.cron import CronTrigger

import config
import db
import matching
from console import auth
from console.auth import login_required, admin_required

ui = Blueprint("ui", __name__)

PAGE_SIZES = (10, 25, 50, 100)


def _worker():
    return current_app.config["WORKER"]


def _sched():
    return current_app.config["SCHEDULER"]


# auth

@ui.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = db.get_user_by_username(username)
        if user and user["active"] and auth.verify_password(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("ui.dashboard"))
        flash("invalid credentials", "error")
    return render_template("login.html")


@ui.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("ui.login"))


@ui.route("/help")
@login_required
def help_page():
    return render_template("help.html")


# dashboard and workspaces

def _system_status():
    worker = _worker()
    scheduler = _sched()
    cfg = current_app.config["APP_CONFIG"]
    tor = getattr(worker, "tor", None)
    tor_state = tor.status() if tor is not None and hasattr(tor, "status") else "unknown"
    sched = scheduler.status() if hasattr(scheduler, "status") else {"running": False, "jobs": 0}
    return {
        "tor": tor_state,
        "pool_size": getattr(cfg, "worker_pool_size", 0),
        "running_jobs": db.count_running(),
        "scheduler_running": sched["running"],
        "scheduler_jobs": sched["jobs"],
    }


@ui.route("/")
@login_required
def dashboard():
    user = g.user
    if user["role"] == "admin":
        workspaces = db.list_workspaces()
    else:
        workspaces = db.list_workspaces_for_user(user["id"])
    visible_ids = [w["id"] for w in workspaces]

    recent = db.list_recent_jobs_for_workspaces(visible_ids, 15)
    status_counts = db.findings_status_counts(visible_ids)
    source_counts = db.findings_source_counts(visible_ids)
    day_counts = db.jobs_per_day(visible_ids, 7)

    finding_bars = [
        {"label": "new", "value": status_counts.get("new", 0)},
        {"label": "confirmed", "value": status_counts.get("confirmed", 0)},
        {"label": "dismissed", "value": status_counts.get("dismissed", 0)},
    ]
    source_bars = [{"label": r["source"], "value": r["c"]} for r in source_counts]
    job_bars = [{"label": r["day"][5:], "value": r["c"]} for r in reversed(day_counts)]

    system = _system_status() if user["role"] == "admin" else None
    return render_template(
        "dashboard.html",
        workspaces=workspaces,
        recent=recent,
        finding_bars=finding_bars,
        source_bars=source_bars,
        job_bars=job_bars,
        system=system,
    )


@ui.route("/workspaces", methods=["POST"])
@admin_required
def create_workspace():
    name = request.form.get("name", "").strip()
    client = request.form.get("client", "").strip()
    if not name:
        flash("workspace name required", "error")
        return redirect(url_for("ui.dashboard"))
    if db.get_workspace_by_name(name):
        flash("workspace already exists", "error")
        return redirect(url_for("ui.dashboard"))
    db.create_workspace(name, client, g.user["id"])
    flash("workspace created", "ok")
    return redirect(url_for("ui.dashboard"))


@ui.route("/workspaces/<int:wid>")
@login_required
def workspace_detail(wid):
    ws = db.get_workspace(wid)
    if ws is None:
        abort(404)
    if not auth.can_access_workspace(g.user, wid):
        abort(403)
    status = request.args.get("status") or None
    try:
        per_page = int(request.args.get("per_page", "10"))
    except ValueError:
        per_page = 10
    if per_page not in PAGE_SIZES:
        per_page = 10
    total = db.count_findings(wid, status)
    pages = max(1, (total + per_page - 1) // per_page)
    try:
        page = int(request.args.get("page", "1"))
    except ValueError:
        page = 1
    page = max(1, min(page, pages))
    offset = (page - 1) * per_page
    findings = db.list_findings(wid, status, limit=per_page, offset=offset)
    return render_template(
        "workspace.html",
        ws=ws,
        terms=db.list_watch_terms(wid),
        schedules=db.list_schedules(wid),
        jobs=db.list_jobs(wid, 15),
        findings=findings,
        source_map=db.finding_sources_map([f["id"] for f in findings]),
        counts=db.count_findings_by_status(wid),
        sources=db.list_enabled_sources(),
        term_types=matching.TERM_TYPES,
        status=status,
        per_page=per_page,
        page=page,
        pages=pages,
        total=total,
        page_sizes=PAGE_SIZES,
    )


# watch terms

@ui.route("/workspaces/<int:wid>/terms", methods=["POST"])
@login_required
def add_term(wid):
    ws = db.get_workspace(wid)
    if ws is None:
        abort(404)
    if not auth.can_access_workspace(g.user, wid):
        abort(403)
    term = request.form.get("term", "").strip()
    term_type = request.form.get("term_type", "").strip()
    if term_type not in matching.TERM_TYPES:
        flash("invalid term type", "error")
        return redirect(url_for("ui.workspace_detail", wid=wid))
    if term_type in ("literal", "regex") and not term:
        flash("literal and regex terms require a value", "error")
        return redirect(url_for("ui.workspace_detail", wid=wid))
    db.create_watch_term(wid, term, term_type)
    flash("term added", "ok")
    return redirect(url_for("ui.workspace_detail", wid=wid))


@ui.route("/terms/<int:tid>/toggle", methods=["POST"])
@login_required
def toggle_term(tid):
    term = db.get_watch_term(tid)
    if term is None:
        abort(404)
    if not auth.can_access_workspace(g.user, term["workspace_id"]):
        abort(403)
    db.set_watch_term_enabled(tid, not term["enabled"])
    return redirect(url_for("ui.workspace_detail", wid=term["workspace_id"]))


@ui.route("/terms/<int:tid>/delete", methods=["POST"])
@login_required
def delete_term(tid):
    term = db.get_watch_term(tid)
    if term is None:
        abort(404)
    if not auth.can_access_workspace(g.user, term["workspace_id"]):
        abort(403)
    db.delete_watch_term(tid)
    flash("term removed", "ok")
    return redirect(url_for("ui.workspace_detail", wid=term["workspace_id"]))


# run and schedules

@ui.route("/workspaces/<int:wid>/run", methods=["POST"])
@login_required
def run_now(wid):
    ws = db.get_workspace(wid)
    if ws is None:
        abort(404)
    if not auth.can_access_workspace(g.user, wid):
        abort(403)
    subset = request.form.getlist("sources") or None
    job_id = _worker().submit_job(wid, "manual", subset, g.user["id"])
    flash("job %d queued" % job_id, "ok")
    return redirect(url_for("ui.workspace_detail", wid=wid))


@ui.route("/workspaces/<int:wid>/schedules", methods=["POST"])
@login_required
def add_schedule(wid):
    ws = db.get_workspace(wid)
    if ws is None:
        abort(404)
    if not auth.can_access_workspace(g.user, wid):
        abort(403)
    name = request.form.get("name", "").strip()
    frequency = request.form.get("frequency", "").strip()
    subset = request.form.getlist("sources") or None
    interval_seconds = None
    cron = None
    presets = ("hourly", "daily", "weekly", "monthly")
    if frequency in presets:
        kind = frequency
    elif frequency == "other":
        custom_kind = request.form.get("custom_kind", "").strip()
        if custom_kind == "interval":
            kind = "interval"
            try:
                interval_seconds = int(request.form.get("interval_seconds", "0"))
            except ValueError:
                interval_seconds = 0
            if interval_seconds < 60:
                flash("interval must be at least 60 seconds", "error")
                return redirect(url_for("ui.workspace_detail", wid=wid))
        elif custom_kind == "cron":
            kind = "cron"
            cron = request.form.get("cron", "").strip()
            try:
                CronTrigger.from_crontab(cron)
            except Exception:
                flash("invalid cron expression", "error")
                return redirect(url_for("ui.workspace_detail", wid=wid))
        else:
            flash("choose interval or cron for a custom schedule", "error")
            return redirect(url_for("ui.workspace_detail", wid=wid))
    else:
        flash("choose a frequency", "error")
        return redirect(url_for("ui.workspace_detail", wid=wid))
    sid = db.create_schedule(wid, name, kind, interval_seconds, cron, subset, g.user["id"])
    _sched().add_schedule(db.get_schedule(sid))
    flash("schedule created", "ok")
    return redirect(url_for("ui.workspace_detail", wid=wid))


@ui.route("/schedules/<int:sid>/toggle", methods=["POST"])
@login_required
def toggle_schedule(sid):
    sch = db.get_schedule(sid)
    if sch is None:
        abort(404)
    if not auth.can_access_workspace(g.user, sch["workspace_id"]):
        abort(403)
    new_state = not sch["enabled"]
    db.set_schedule_enabled(sid, new_state)
    if new_state:
        _sched().add_schedule(db.get_schedule(sid))
    else:
        _sched().remove_schedule(sid)
    return redirect(url_for("ui.workspace_detail", wid=sch["workspace_id"]))


@ui.route("/schedules/<int:sid>/delete", methods=["POST"])
@login_required
def delete_schedule(sid):
    sch = db.get_schedule(sid)
    if sch is None:
        abort(404)
    if not auth.can_access_workspace(g.user, sch["workspace_id"]):
        abort(403)
    _sched().remove_schedule(sid)
    db.delete_schedule(sid)
    flash("schedule removed", "ok")
    return redirect(url_for("ui.workspace_detail", wid=sch["workspace_id"]))


# findings and jobs

@ui.route("/findings/<int:fid>")
@login_required
def finding_detail(fid):
    finding = db.get_finding(fid)
    if finding is None:
        abort(404)
    if not auth.can_access_workspace(g.user, finding["workspace_id"]):
        abort(403)
    matches = db.list_matches_for_finding(fid)
    analyses = db.list_analyses_for_finding(fid)
    return render_template("finding.html", f=finding, matches=matches,
                           analyses=analyses, finding_sources=db.list_finding_sources(fid))


@ui.route("/findings/<int:fid>/status", methods=["POST"])
@login_required
def finding_status(fid):
    finding = db.get_finding(fid)
    if finding is None:
        abort(404)
    if not auth.can_access_workspace(g.user, finding["workspace_id"]):
        abort(403)
    status = request.form.get("status", "").strip()
    if status not in ("new", "confirmed", "dismissed"):
        flash("invalid status", "error")
        return redirect(url_for("ui.workspace_detail", wid=finding["workspace_id"]))
    db.set_finding_status(fid, status)
    nxt = request.form.get("next")
    return redirect(nxt or url_for("ui.workspace_detail", wid=finding["workspace_id"]))


@ui.route("/findings/<int:fid>/analyze", methods=["POST"])
@login_required
def analyze_finding(fid):
    finding = db.get_finding(fid)
    if finding is None:
        abort(404)
    if not auth.can_access_workspace(g.user, finding["workspace_id"]):
        abort(403)
    analysis_id = _worker().submit_analysis(
        fid, finding["workspace_id"], finding["url"], g.user["id"])
    flash("analysis queued", "ok")
    return redirect(url_for("ui.analysis_report", aid=analysis_id))


@ui.route("/analyses/<int:aid>")
@login_required
def analysis_report(aid):
    analysis = db.get_analysis(aid)
    if analysis is None:
        abort(404)
    if not auth.can_access_workspace(g.user, analysis["workspace_id"]):
        abort(403)
    finding = db.get_finding(analysis["finding_id"])
    stats = json.loads(analysis["stats_json"]) if analysis["stats_json"] else {}
    pages = db.list_analysis_pages(aid) if analysis["status"] == "completed" else []
    onion_links = []
    seen = set()
    for page in pages:
        page["links"] = json.loads(page["links_json"]) if page["links_json"] else []
        for link in page["links"]:
            if link.get("is_onion") and link["url"] not in seen:
                seen.add(link["url"])
                onion_links.append(link["url"])
    return render_template(
        "report.html", analysis=analysis, finding=finding,
        pages=pages, stats=stats, onion_links=onion_links)


@ui.route("/jobs/<int:jid>")
@login_required
def job_detail(jid):
    job = db.get_job(jid)
    if job is None:
        abort(404)
    if not auth.can_access_workspace(g.user, job["workspace_id"]):
        abort(403)
    stats = json.loads(job["stats_json"]) if job["stats_json"] else {}
    return render_template("job.html", job=job, stats=stats)


# admin users

@ui.route("/admin/users")
@admin_required
def admin_users():
    users = db.list_users()
    workspaces = db.list_workspaces()
    membership = {u["id"]: [w["id"] for w in db.list_workspaces_for_user(u["id"])] for u in users}
    return render_template("users.html", users=users, workspaces=workspaces, membership=membership)


@ui.route("/admin/users", methods=["POST"])
@admin_required
def create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "operator").strip()
    if not username or not password:
        flash("username and password required", "error")
        return redirect(url_for("ui.admin_users"))
    if role not in ("admin", "operator"):
        flash("invalid role", "error")
        return redirect(url_for("ui.admin_users"))
    if db.get_user_by_username(username):
        flash("user already exists", "error")
        return redirect(url_for("ui.admin_users"))
    db.create_user(username, auth.hash_password(password), role)
    flash("user created", "ok")
    return redirect(url_for("ui.admin_users"))


@ui.route("/admin/users/<int:uid>/toggle", methods=["POST"])
@admin_required
def toggle_user(uid):
    user = db.get_user(uid)
    if user is None:
        abort(404)
    db.set_user_active(uid, not user["active"])
    return redirect(url_for("ui.admin_users"))


@ui.route("/admin/users/<int:uid>/workspaces", methods=["POST"])
@admin_required
def assign_workspaces(uid):
    user = db.get_user(uid)
    if user is None:
        abort(404)
    selected = set(request.form.getlist("workspaces"))
    current = set(str(w["id"]) for w in db.list_workspaces_for_user(uid))
    for wid in selected - current:
        db.add_membership(uid, int(wid))
    for wid in current - selected:
        db.remove_membership(uid, int(wid))
    flash("memberships updated", "ok")
    return redirect(url_for("ui.admin_users"))


# admin sources

@ui.route("/admin/sources")
@admin_required
def admin_sources():
    sources = db.list_sources()
    for source in sources:
        try:
            cfg = json.loads(source["config_json"] or "{}")
        except ValueError:
            cfg = {}
        source["base_url"] = cfg.get("base_url", "")
    return render_template("sources.html", sources=sources)


@ui.route("/admin/sources/<int:sid>/toggle", methods=["POST"])
@admin_required
def toggle_source(sid):
    source = db.get_source(sid)
    if source is None:
        abort(404)
    db.set_source_enabled(sid, not source["enabled"])
    return redirect(url_for("ui.admin_sources"))


@ui.route("/admin/sources/<int:sid>/config", methods=["POST"])
@admin_required
def source_config(sid):
    source = db.get_source(sid)
    if source is None:
        abort(404)
    base_url = request.form.get("base_url", "").strip()
    try:
        cfg = json.loads(source["config_json"] or "{}")
    except ValueError:
        cfg = {}
    if base_url:
        cfg["base_url"] = base_url
    else:
        cfg.pop("base_url", None)
    db.update_source_config(sid, cfg)
    flash("source updated", "ok")
    return redirect(url_for("ui.admin_sources"))


# admin settings

def _validate_setting(spec, raw):
    kind = spec["type"]
    if kind == "int":
        try:
            number = int(raw)
        except (ValueError, TypeError):
            return False, None, "must be a whole number"
        if "min" in spec and number < spec["min"]:
            return False, None, "minimum is %d" % spec["min"]
        if "max" in spec and number > spec["max"]:
            return False, None, "maximum is %d" % spec["max"]
        return True, str(number), ""
    if kind == "bool":
        value = "true" if str(raw).strip().lower() in ("1", "true", "yes", "on") else "false"
        return True, value, ""
    text = str(raw).strip()
    if not text:
        return False, None, "cannot be empty"
    if len(text) > 500:
        return False, None, "too long"
    return True, text, ""


@ui.route("/admin/settings")
@admin_required
def admin_settings():
    cfg = config.Config()
    overrides = db.get_settings()
    rows = []
    for spec in config.SETTINGS:
        name = spec["name"]
        if name in overrides:
            source = "saved"
        elif spec["env"] in os.environ and os.environ[spec["env"]] != "":
            source = "env"
        else:
            source = "default"
        rows.append({
            "name": name,
            "label": spec["label"],
            "group": spec["group"],
            "type": spec["type"],
            "value": getattr(cfg, name),
            "source": source,
            "min": spec.get("min"),
            "max": spec.get("max"),
            "default": spec["default"],
        })
    live = [r for r in rows if r["group"] == "live"]
    restart = [r for r in rows if r["group"] == "restart"]
    return render_template("settings.html", live=live, restart=restart)


@ui.route("/admin/settings", methods=["POST"])
@admin_required
def save_settings():
    errors = []
    for spec in config.SETTINGS:
        name = spec["name"]
        if request.form.get("reset_" + name):
            db.delete_setting(name)
            continue
        ok, value, msg = _validate_setting(spec, request.form.get(name, ""))
        if not ok:
            errors.append("%s %s" % (spec["label"], msg))
            continue
        db.set_setting(name, value)
    if errors:
        for message in errors:
            flash(message, "error")
    else:
        flash("settings saved, live values apply to the next job", "ok")
    return redirect(url_for("ui.admin_settings"))
