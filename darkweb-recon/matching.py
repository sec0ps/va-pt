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
# Purpose: Watch-term entity extractors, phrase/literal matchers, and the content match engine for the darkweb recon subsystem. Provides case-insensitive full-phrase literal matching, typed extractors (email, domain, ip, crypto, hash, credential, card) that can be scoped to a term, credential/card masking, and query-string construction that phrase-quotes multi-word literal terms.
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
# Location: darkweb-recon/matching.py

"""Watch-term entity extractors and match engine."""

import re

TERM_TYPES = (
    "literal",
    "regex",
    "domain",
    "email",
    "ipv4",
    "ipv6",
    "credential",
    "card",
    "btc",
    "eth",
    "hash",
)

# NOTE snippet-only matching for now, tagged for deep-body expansion in a later increment.
# Extractor terms scan the returned title and snippet. Deep matching against the fetched
# onion page body is intentionally not wired here yet.

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")
BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
CRED_RE = re.compile(
    r"([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}|[A-Za-z0-9._\-]{3,32})[:|]([^\s:|]{4,64})")
CARD_CANDIDATE_RE = re.compile(r"\d(?:[ \-]?\d){12,18}")

EXTRACTORS = {
    "email": EMAIL_RE,
    "domain": DOMAIN_RE,
    "ipv4": IPV4_RE,
    "ipv6": IPV6_RE,
    "btc": BTC_RE,
    "eth": ETH_RE,
    "hash": HASH_RE,
}


def luhn_valid(digits):
    total = 0
    reverse = digits[::-1]
    for index, char in enumerate(reverse):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def mask_secret(value):
    if len(value) <= 2:
        return "*" * len(value)
    return "*" * (len(value) - 2) + value[-2:]


def mask_pan(digits):
    if len(digits) <= 10:
        return "*" * len(digits)
    return digits[:6] + "*" * (len(digits) - 10) + digits[-4:]


class Matcher:
    def __init__(self, term_id, term, term_type, mask_credentials, per_term_cap, value_cap):
        self.term_id = term_id
        self.term = (term or "").strip()
        self.term_type = term_type
        self.mask_credentials = mask_credentials
        self.per_term_cap = per_term_cap
        self.value_cap = value_cap

    def apply(self, text):
        if not text:
            return []
        found = self._match(text)
        result = []
        seen = set()
        for value in found:
            value = value[: self.value_cap]
            if value in seen:
                continue
            seen.add(value)
            result.append(value)
            if len(result) >= self.per_term_cap:
                break
        return result

    def _match(self, text):
        handler = getattr(self, "_match_%s" % self.term_type, None)
        if handler is None:
            return []
        return handler(text)

    def _match_literal(self, text):
        if not self.term:
            return []
        if self.term.lower() in text.lower():
            return [self.term]
        return []

    def _match_regex(self, text):
        if not self.term:
            return []
        try:
            pattern = re.compile(self.term, re.IGNORECASE)
        except re.error:
            return []
        return [m.group(0) for m in pattern.finditer(text)]

    def _match_extractor(self, text, pattern):
        if self.term:
            target = self.term.lower()
            return [m.group(0) for m in pattern.finditer(text)
                    if target in m.group(0).lower()]
        return [m.group(0) for m in pattern.finditer(text)]

    def _match_domain(self, text):
        return self._match_extractor(text, DOMAIN_RE)

    def _match_email(self, text):
        return self._match_extractor(text, EMAIL_RE)

    def _match_ipv4(self, text):
        return self._match_extractor(text, IPV4_RE)

    def _match_ipv6(self, text):
        return self._match_extractor(text, IPV6_RE)

    def _match_btc(self, text):
        return self._match_extractor(text, BTC_RE)

    def _match_eth(self, text):
        return self._match_extractor(text, ETH_RE)

    def _match_hash(self, text):
        return self._match_extractor(text, HASH_RE)

    def _match_credential(self, text):
        results = []
        for match in CRED_RE.finditer(text):
            user = match.group(1)
            secret = match.group(2)
            if self.term and self.term.lower() != user.lower():
                continue
            if self.mask_credentials:
                secret = mask_secret(secret)
            results.append("%s:%s" % (user, secret))
        return results

    def _match_card(self, text):
        results = []
        for match in CARD_CANDIDATE_RE.finditer(text):
            digits = re.sub(r"[ \-]", "", match.group(0))
            if not (13 <= len(digits) <= 19):
                continue
            if not luhn_valid(digits):
                continue
            if self.term and not digits.startswith(re.sub(r"\D", "", self.term)):
                continue
            if self.mask_credentials:
                results.append(mask_pan(digits))
            else:
                results.append(digits)
        return results


def build_matchers(terms, config):
    matchers = []
    for term in terms:
        matchers.append(Matcher(
            term_id=term["id"],
            term=term["term"],
            term_type=term["term_type"],
            mask_credentials=config.credential_mask,
            per_term_cap=config.match_per_term_cap,
            value_cap=config.match_value_max_chars,
        ))
    return matchers


def scan_text(text, matchers):
    matches = []
    for matcher in matchers:
        for value in matcher.apply(text):
            matches.append({
                "term_id": matcher.term_id,
                "term_type": matcher.term_type,
                "value": value,
            })
    return matches


def queryable_terms(terms):
    result = []
    for term in terms:
        if term["term_type"] == "regex":
            continue
        value = (term["term"] or "").strip()
        if not value:
            continue
        result.append(term)
    return result


def query_for_term(term):
    # Phrase-quote multi-word literal terms so phrase-aware engines return pages
    # containing the whole phrase rather than any single token. A client name like
    # "Kevin Mitnick" is sent quoted; single-token and non-literal terms are sent
    # as-is. Provenance still records the unquoted term for display.
    value = (term["term"] or "").strip()
    if term.get("term_type") == "literal" and " " in value and '"' not in value:
        return '"%s"' % value
    return value
