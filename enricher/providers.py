"""Threat-intel providers: VirusTotal, AbuseIPDB, URLhaus.

Each provider turns an Indicator into a ProviderResult with a 0-100 score
(or None if the provider had no opinion) and a short human summary.
"""

from __future__ import annotations

import base64
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests

from .http import ProviderError, request_with_retry
from .indicators import Indicator, human_size

MAX_LISTED = 8  # cap on names/detections shown per file


@dataclass
class ProviderResult:
    provider: str
    status: str  # "ok" | "not_found" | "skipped" | "error"
    score: int | None = None
    summary: str = ""
    details: dict = field(default_factory=dict)
    facts: list[str] = field(default_factory=list)  # extra human-readable lines for reports


def _date(timestamp) -> str:
    return datetime.fromtimestamp(int(timestamp), timezone.utc).strftime("%Y-%m-%d")


class Provider:
    name = "base"
    supported_kinds: tuple[str, ...] = ()
    needs_key = True

    def __init__(self, api_key: str | None, session: requests.Session | None = None):
        self.api_key = api_key
        self.session = session or requests.Session()

    def supports(self, indicator: Indicator) -> bool:
        return indicator.kind in self.supported_kinds

    def lookup(self, indicator: Indicator) -> ProviderResult:
        if not self.supports(indicator):
            return ProviderResult(self.name, "skipped", summary="indicator type not supported")
        if self.needs_key and not self.api_key:
            return ProviderResult(self.name, "skipped", summary="no API key configured")
        try:
            return self._lookup(indicator)
        except ProviderError as exc:
            return ProviderResult(self.name, "error", summary=str(exc))

    def _lookup(self, indicator: Indicator) -> ProviderResult:  # pragma: no cover
        raise NotImplementedError


class VirusTotal(Provider):
    name = "VirusTotal"
    supported_kinds = ("ip", "domain", "url", "hash")
    BASE = "https://www.virustotal.com/api/v3"

    def _path(self, ind: Indicator) -> str:
        if ind.kind == "ip":
            return f"/ip_addresses/{ind.value}"
        if ind.kind == "domain":
            return f"/domains/{ind.value}"
        if ind.kind == "hash":
            return f"/files/{ind.value}"
        url_id = base64.urlsafe_b64encode(ind.value.encode()).decode().rstrip("=")
        return f"/urls/{url_id}"

    def _lookup(self, ind: Indicator) -> ProviderResult:
        resp = request_with_retry(
            self.session, "GET", self.BASE + self._path(ind), headers={"x-apikey": self.api_key}
        )
        if resp.status_code == 404:
            return ProviderResult(self.name, "not_found", summary="not seen by VirusTotal")
        if resp.status_code in (401, 403):
            raise ProviderError("authentication failed (check VT_API_KEY)")
        if resp.status_code != 200:
            raise ProviderError(f"unexpected HTTP {resp.status_code}")

        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) or 0
        score = min(100, malicious * 12 + suspicious * 5)
        return ProviderResult(
            self.name,
            "ok",
            score=score,
            summary=f"{malicious} malicious / {suspicious} suspicious of {total} engines",
            details={"stats": stats, "reputation": attrs.get("reputation")},
            facts=self._file_facts(ind, attrs) if ind.kind == "hash" else [],
        )

    @staticmethod
    def _file_facts(ind: Indicator, attrs: dict) -> list[str]:
        """Describe a file from VirusTotal's record: what it is and who flagged it."""
        facts: list[str] = []

        what = [attrs.get("type_description") or ""]
        if attrs.get("size") is not None:
            what.append(human_size(int(attrs["size"])))
        if any(what):
            facts.append("type: " + ", ".join(w for w in what if w))

        names = [n for n in attrs.get("names") or [] if n]
        if names:
            facts.append("known as: " + ", ".join(names[:MAX_LISTED]))

        sig = attrs.get("signature_info") or {}
        if sig.get("verified") or sig.get("signers"):
            signer = (sig.get("signers") or "").split(";")[0].strip()
            facts.append(
                f"signature: {sig.get('verified') or 'not verified'}"
                + (f" ({signer})" if signer else "")
            )

        label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
        if label:
            facts.append(f"threat label: {label}")

        flagged = sorted(
            f"{engine}: {res.get('result') or res.get('category')}"
            for engine, res in (attrs.get("last_analysis_results") or {}).items()
            if res.get("category") in ("malicious", "suspicious")
        )
        if flagged:
            more = len(flagged) - MAX_LISTED
            facts.append(
                "flagged by: " + "; ".join(flagged[:MAX_LISTED]) + (f" (+{more} more)" if more > 0 else "")
            )

        history = []
        if attrs.get("first_submission_date"):
            history.append(f"first seen {_date(attrs['first_submission_date'])}")
        if attrs.get("last_analysis_date"):
            history.append(f"last scanned {_date(attrs['last_analysis_date'])}")
        if attrs.get("times_submitted"):
            history.append(f"submitted {attrs['times_submitted']} time(s)")
        if history:
            facts.append("history: " + ", ".join(history))

        facts.append(f"report: https://www.virustotal.com/gui/file/{ind.value}")
        return facts


class AbuseIPDB(Provider):
    name = "AbuseIPDB"
    supported_kinds = ("ip",)
    URL = "https://api.abuseipdb.com/api/v2/check"

    def _lookup(self, ind: Indicator) -> ProviderResult:
        resp = request_with_retry(
            self.session,
            "GET",
            self.URL,
            headers={"Key": self.api_key, "Accept": "application/json"},
            params={"ipAddress": ind.value, "maxAgeInDays": 90},
        )
        if resp.status_code in (401, 403):
            raise ProviderError("authentication failed (check ABUSEIPDB_API_KEY)")
        if resp.status_code != 200:
            raise ProviderError(f"unexpected HTTP {resp.status_code}")

        data = resp.json().get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
        return ProviderResult(
            self.name,
            "ok",
            score=score,
            summary=(
                f"abuse confidence {score}%, {data.get('totalReports', 0)} reports "
                f"({data.get('countryCode') or '??'}, {data.get('isp') or 'unknown ISP'})"
            ),
            details={
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
                "total_reports": data.get("totalReports"),
            },
        )


class URLhaus(Provider):
    """abuse.ch URLhaus. Requires a free Auth-Key from https://auth.abuse.ch/."""

    name = "URLhaus"
    supported_kinds = ("ip", "domain", "url")
    BASE = "https://urlhaus-api.abuse.ch/v1"

    def _lookup(self, ind: Indicator) -> ProviderResult:
        if ind.kind == "url":
            endpoint, payload = "/url/", {"url": ind.value}
        else:
            endpoint, payload = "/host/", {"host": ind.value}

        resp = request_with_retry(
            self.session,
            "POST",
            self.BASE + endpoint,
            headers={"Auth-Key": self.api_key},
            data=payload,
        )
        if resp.status_code in (401, 403):
            raise ProviderError("authentication failed (check URLHAUS_AUTH_KEY)")
        if resp.status_code != 200:
            raise ProviderError(f"unexpected HTTP {resp.status_code}")

        body = resp.json()
        status = body.get("query_status")
        if status in ("no_results", "invalid_url", "invalid_host"):
            return ProviderResult(self.name, "not_found", summary="no malware URLs on record")
        if status != "ok":
            raise ProviderError(f"query status: {status}")

        if ind.kind == "url":
            online = body.get("url_status") == "online"
            threat = body.get("threat") or "malware_download"
            score = 95 if online else 80
            summary = f"listed as {threat} ({body.get('url_status', 'unknown')})"
        else:
            count = int(body.get("url_count", 0))
            score = 90 if count else 0
            summary = f"{count} malware URL(s) hosted"
        return ProviderResult(self.name, "ok", score=score, summary=summary)


class MalwareBazaar(Provider):
    """abuse.ch MalwareBazaar: a database of confirmed malware samples."""

    name = "MalwareBazaar"
    supported_kinds = ("hash",)
    URL = "https://mb-api.abuse.ch/api/v1/"
    LISTED_SCORE = 95  # only confirmed malware is listed

    def _lookup(self, ind: Indicator) -> ProviderResult:
        resp = request_with_retry(
            self.session,
            "POST",
            self.URL,
            headers={"Auth-Key": self.api_key},
            data={"query": "get_info", "hash": ind.value},
        )
        if resp.status_code in (401, 403):
            raise ProviderError("authentication failed (check MALWAREBAZAAR_AUTH_KEY)")
        if resp.status_code != 200:
            raise ProviderError(f"unexpected HTTP {resp.status_code}")

        body = resp.json()
        status = body.get("query_status")
        if status in ("hash_not_found", "no_results"):
            return ProviderResult(self.name, "not_found", summary="not a known malware sample")
        if status != "ok":
            raise ProviderError(f"query status: {status}")

        data = body.get("data")
        sample = data[0] if isinstance(data, list) and data else body
        family = sample.get("signature")
        facts = []
        if sample.get("tags"):
            facts.append("tags: " + ", ".join(str(t) for t in sample["tags"][:MAX_LISTED]))
        seen_as = [str(sample[k]) for k in ("file_name", "file_type") if sample.get(k)]
        if seen_as:
            facts.append("seen as: " + ", ".join(seen_as))
        if sample.get("first_seen"):
            facts.append(f"first seen: {sample['first_seen']}")
        if sample.get("delivery_method"):
            facts.append(f"delivered via: {sample['delivery_method']}")
        facts.append(f"report: https://bazaar.abuse.ch/sample/{sample.get('sha256_hash') or ind.value}/")
        return ProviderResult(
            self.name,
            "ok",
            score=self.LISTED_SCORE,
            summary=f"known malware sample, family: {family or 'unidentified'}",
            details={"family": family, "tags": sample.get("tags")},
            facts=facts,
        )


def whois_query(query: str, host: str = "hash.cymru.com", port: int = 43, timeout: int = 10) -> str:
    """Send one WHOIS query and return the full text reply."""
    with socket.create_connection((host, port), timeout=timeout) as conn:
        conn.sendall(query.encode() + b"\r\n")
        chunks = []
        while chunk := conn.recv(4096):
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


class TeamCymru(Provider):
    """Team Cymru Malware Hash Registry, queried over WHOIS. No key needed."""

    name = "Team Cymru MHR"
    supported_kinds = ("hash",)
    needs_key = False
    LISTED_FLOOR = 30  # being listed at all is at least suspicious

    def __init__(self, api_key: str | None = None, session=None, query=whois_query):
        super().__init__(api_key, session)
        self.query = query

    def _lookup(self, ind: Indicator) -> ProviderResult:
        try:
            reply = self.query(ind.value)
        except OSError as exc:
            raise ProviderError(f"network error: {exc.__class__.__name__} (WHOIS port 43)") from exc

        for line in reply.splitlines():
            parts = line.split()
            if len(parts) < 2 or parts[0].lower() != ind.value:
                continue
            # Unlisted hashes come back as "<hash> NO_DATA" or "<hash> <epoch> NO_DATA".
            if parts[-1] == "NO_DATA":
                return ProviderResult(self.name, "not_found", summary="not in the malware registry")
            if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
                rate = int(parts[2])
                return ProviderResult(
                    self.name,
                    "ok",
                    score=max(self.LISTED_FLOOR, min(100, rate)),
                    summary=f"listed as malware, {rate}% antivirus detection rate",
                    details={"detection_rate": rate},
                    facts=[f"last seen: {_date(parts[1])}"],
                )
        raise ProviderError("unexpected response from hash.cymru.com")


def build_providers(env: dict[str, str], session: requests.Session | None = None) -> list[Provider]:
    return [
        VirusTotal(env.get("VT_API_KEY"), session),
        AbuseIPDB(env.get("ABUSEIPDB_API_KEY"), session),
        URLhaus(env.get("URLHAUS_AUTH_KEY"), session),
        # abuse.ch issues one Auth-Key for all its services, so the URLhaus key works here.
        MalwareBazaar(env.get("MALWAREBAZAAR_AUTH_KEY") or env.get("URLHAUS_AUTH_KEY"), session),
        TeamCymru(),
    ]
