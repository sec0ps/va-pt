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
# Purpose: Bounded worker pool for the darkweb recon subsystem. Executes search jobs by querying enabled engines over Tor, deduplicates results into findings, records per-engine provenance separately from content matches, and scans result title/snippet for watch terms. Also runs on-demand site analyses that fetch an onion over Tor into an inert report.
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
# Location: darkweb-recon/worker.py

"""Bounded worker pool that executes search jobs, runs matching, and persists findings."""

import json
import time
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
        self.config.refresh()
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
                 "findings_seen": 0, "matches_added": 0, "source_errors": 0,
                 "bodies_fetched": 0}

        if not terms:
            db.mark_job_finished(job_id, "completed", stats, None)
            return

        matchers = matching.build_matchers(terms, self.config)
        queries = matching.queryable_terms(terms)
        sources = self.registry.search_sources(subset)
        isolation = "ws%d" % workspace_id
        # Per-job body-match budget: fetch at most body_match_cap distinct result
        # pages this run (0 disables), tracked across all sources/terms.
        body_ctx = {
            "budget": self.config.body_match_cap if self.config.body_match else 0,
            "fetched": set(),
        }

        for source in sources:
            for term in queries:
                stats["terms_queried"] += 1
                try:
                    hits = source.search(
                        matching.query_for_term(term), self.fetcher, isolation=isolation,
                        limit=self.config.match_per_term_cap * 4)
                except (FetchError, TorError) as exc:
                    stats["source_errors"] += 1
                    log.warning("source %s term %s failed: %s", source.name, term["id"], exc)
                    continue
                self._ingest(workspace_id, job_id, hits, term, matchers,
                             source.name, isolation, body_ctx, stats)

        db.mark_job_finished(job_id, "completed", stats, None)

    def _ingest(self, workspace_id, job_id, hits, query_term, matchers,
                source_name, isolation, body_ctx, stats):
        for hit in hits:
            stats["hits"] += 1
            record = hit.as_dict()
            finding_id, is_new = db.upsert_finding(
                workspace_id, job_id, record, self.config.snippet_max_chars)
            if is_new:
                stats["findings_new"] += 1
            else:
                stats["findings_seen"] += 1

            # Provenance only: which engine + query surfaced this URL. Recorded
            # separately from matches so it is never mistaken for content found on
            # the page (a URL returned by a query is not evidence the term is on it).
            db.record_finding_source(finding_id, source_name, query_term["term"])

            # Match watch terms against the title/snippet, and (gated) the fetched
            # page body, so a name that only appears in the page content still hits.
            blob = "%s %s" % (record["title"] or "", record["snippet"] or "")
            if body_ctx["budget"] > 0 and finding_id not in body_ctx["fetched"]:
                body = self.analyzer.page_text(
                    record["url"], self.fetcher, isolation=isolation)
                body_ctx["fetched"].add(finding_id)
                body_ctx["budget"] -= 1
                stats["bodies_fetched"] += 1
                if body:
                    blob = "%s %s" % (blob, body)
                if self.config.body_match_delay:
                    time.sleep(self.config.body_match_delay)

            for match in matching.scan_text(blob, matchers):
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
        self.config.refresh()
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
