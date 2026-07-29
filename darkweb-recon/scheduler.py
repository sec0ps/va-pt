"""APScheduler wrapper that enqueues scheduled jobs into the worker pool."""

import json
import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

import db

log = logging.getLogger("recon.scheduler")

PRESET_CRON = {
    "hourly": "0 * * * *",
    "daily": "0 0 * * *",
    "weekly": "0 0 * * 0",
    "monthly": "0 0 1 * *",
}


class Scheduler:
    def __init__(self, worker):
        self.worker = worker
        self._scheduler = BackgroundScheduler()

    def start(self):
        self._scheduler.start()
        for row in db.list_enabled_schedules():
            self.add_schedule(row)

    def _trigger(self, row):
        kind = row["kind"]
        if kind in PRESET_CRON:
            return CronTrigger.from_crontab(PRESET_CRON[kind])
        if kind == "interval":
            seconds = row["interval_seconds"] or 3600
            return IntervalTrigger(seconds=seconds)
        if kind == "cron":
            return CronTrigger.from_crontab(row["cron"])
        raise ValueError("unknown schedule kind %s" % kind)

    def add_schedule(self, row):
        try:
            trigger = self._trigger(row)
        except Exception as exc:
            log.error("could not build trigger for schedule %s: %s", row["id"], exc)
            return
        self._scheduler.add_job(
            self._fire, trigger=trigger, args=[row["id"]],
            id=str(row["id"]), replace_existing=True)
        log.info("scheduled job for schedule %s", row["id"])

    def remove_schedule(self, schedule_id):
        try:
            self._scheduler.remove_job(str(schedule_id))
        except Exception:
            pass

    def _fire(self, schedule_id):
        row = db.get_schedule(schedule_id)
        if row is None or not row["enabled"]:
            return
        subset = json.loads(row["source_subset"]) if row["source_subset"] else None
        self.worker.submit_job(row["workspace_id"], "schedule", subset, None)
        db.mark_schedule_run(schedule_id)
        log.info("fired schedule %s for workspace %s", schedule_id, row["workspace_id"])

    def shutdown(self):
        try:
            self._scheduler.shutdown(wait=False)
        except Exception:
            pass

    def status(self):
        try:
            return {"running": self._scheduler.running, "jobs": len(self._scheduler.get_jobs())}
        except Exception:
            return {"running": False, "jobs": 0}
