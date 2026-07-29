"""Bounded worker pool that executes search jobs, runs matching, and persists findings."""

import json
import logging
from concurrent.futures import ThreadPoolExecutor

import db
import matching
from analyzer import Analyzer
from fetch import FetchError
from torctl import TorError

log = logging.getLogger("recon.worker")


class Worker:
    def __init__(self, config, tor_manager, fetcher, registry):
        self.config = config
        self.tor = tor_manager
        self.fetcher = fetcher
        self.registry = registry
        self.analyzer = Analyzer(config)
        self._executor = ThreadPoolExecutor(
            max_workers=config.worker_pool_size, thread_name_prefix="job")

    def submit_job(self, workspace_id, trigger, source_subset, created_by):
        job_id = db.create_job(workspace_id, trigger, source_subset, created_by)
        self._executor.submit(self._run_job, job_id)
        return job_id

    def _run_job(self, job_id):
        try:
            self.execute_job(job_id)
        except Exception as exc:
            log.exception("job %s crashed", job_id)
            db.mark_job_finished(job_id, "failed", None, str(exc))

    def execute_job(self, job_id):
        job = db.get_job(job_id)
        if job is None:
            return
        db.mark_job_running(job_id)
        workspace_id = job["workspace_id"]
        subset = json.loads(job["source_subset"]) if job["source_subset"] else None

        try:
            self.tor.wait_ready(self.config.job_tor_wait)
        except TorError as exc:
            db.mark_job_finished(job_id, "failed", None, "tor not available: %s" % exc)
            return

        terms = db.list_enabled_watch_terms(workspace_id)
        stats = {"terms_queried": 0, "hits": 0, "findings_new": 0,
                 "findings_seen": 0, "matches_added": 0, "source_errors": 0}

        if not terms:
            db.mark_job_finished(job_id, "completed", stats, None)
            return

        matchers = matching.build_matchers(terms, self.config)
        queries = matching.queryable_terms(terms)
        sources = self.registry.search_sources(subset)
        isolation = "ws%d" % workspace_id

        for source in sources:
            for term in queries:
                stats["terms_queried"] += 1
                try:
                    hits = source.search(
                        term["term"], self.fetcher, isolation=isolation,
                        limit=self.config.match_per_term_cap * 4)
                except (FetchError, TorError) as exc:
                    stats["source_errors"] += 1
                    log.warning("source %s term %s failed: %s", source.name, term["id"], exc)
                    continue
                self._ingest(workspace_id, job_id, hits, term, matchers, stats)

        db.mark_job_finished(job_id, "completed", stats, None)

    def _ingest(self, workspace_id, job_id, hits, query_term, matchers, stats):
        for hit in hits:
            stats["hits"] += 1
            record = hit.as_dict()
            finding_id, is_new = db.upsert_finding(
                workspace_id, job_id, record, self.config.snippet_max_chars)
            if is_new:
                stats["findings_new"] += 1
            else:
                stats["findings_seen"] += 1

            provenance = (query_term["term"] or "")[: self.config.match_value_max_chars]
            db.add_finding_match(finding_id, query_term["id"], query_term["term_type"], provenance)
            stats["matches_added"] += 1

            blob = "%s %s" % (record["title"] or "", record["snippet"] or "")
            for match in matching.scan_text(blob, matchers):
                if match["term_id"] == query_term["id"] and match["value"] == provenance:
                    continue
                db.add_finding_match(
                    finding_id, match["term_id"], match["term_type"], match["value"])
                stats["matches_added"] += 1

    def shutdown(self):
        self._executor.shutdown(wait=False, cancel_futures=True)

    def submit_analysis(self, finding_id, workspace_id, root_url, created_by):
        analysis_id = db.create_analysis(finding_id, workspace_id, root_url, created_by)
        self._executor.submit(self._run_analysis, analysis_id)
        return analysis_id

    def _run_analysis(self, analysis_id):
        try:
            self.execute_analysis(analysis_id)
        except Exception as exc:
            log.exception("analysis %s crashed", analysis_id)
            db.mark_analysis_finished(analysis_id, "failed", None, str(exc))

    def execute_analysis(self, analysis_id):
        analysis = db.get_analysis(analysis_id)
        if analysis is None:
            return
        db.mark_analysis_running(analysis_id)

        try:
            self.tor.wait_ready(self.config.job_tor_wait)
        except TorError as exc:
            db.mark_analysis_finished(analysis_id, "failed", None, "tor not available: %s" % exc)
            return

        try:
            pages = self.analyzer.crawl(
                analysis["root_url"], self.fetcher, isolation="an%d" % analysis_id)
        except (FetchError, TorError) as exc:
            db.mark_analysis_finished(analysis_id, "failed", None, str(exc))
            return

        onion_links = set()
        for page in pages:
            db.add_analysis_page(
                analysis_id, page["url"], page["title"], page["text"], page["links"])
            for link in page["links"]:
                if link["is_onion"]:
                    onion_links.add(link["url"])

        stats = {"pages_fetched": len(pages), "onion_links_found": len(onion_links)}
        db.mark_analysis_finished(analysis_id, "completed", stats, None)
