"""Orchestration: classify, query providers (with cache), score."""

from __future__ import annotations

from dataclasses import dataclass, field

from .cache import Cache
from .indicators import Indicator, classify
from .localfile import LocalFile
from .providers import Provider, ProviderResult
from .scoring import combine


@dataclass
class Enrichment:
    raw: str
    indicator: Indicator
    results: list[ProviderResult] = field(default_factory=list)
    score: int | None = None
    verdict: str = "unknown"
    note: str = ""
    label: str = ""  # e.g. the file name when the indicator is a file's hash
    source: str = ""  # e.g. the local path and size of the hashed file
    local: LocalFile | None = None  # offline checks on the hashed file


def enrich(
    raw: str,
    providers: list[Provider],
    cache: Cache | None = None,
    label: str = "",
    source: str = "",
    local: LocalFile | None = None,
) -> Enrichment:
    indicator = classify(raw)
    out = Enrichment(raw=raw, indicator=indicator, label=label, source=source, local=local)

    if indicator.kind == "unknown":
        out.note = "could not recognize indicator type"
        return out
    if indicator.kind == "ip" and not indicator.is_public_ip:
        out.note = "private/reserved IP, not sent to external services"
        return out

    for provider in providers:
        if not provider.supports(indicator):
            continue
        cached = cache.get(provider.name, indicator.value) if cache else None
        if cached:
            result = cached
        else:
            result = provider.lookup(indicator)
            if cache:
                cache.put(provider.name, indicator.value, result)
        out.results.append(result)

    out.score, out.verdict = combine(out.results)
    return out
