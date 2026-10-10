"""Combine provider scores into one explainable verdict.

Rule: the overall score is the highest provider score (one credible source
flagging something is enough to look closer), plus a small corroboration
bonus when two or more providers independently score >= SUSPICIOUS.
"""

from __future__ import annotations

from .providers import ProviderResult

SUSPICIOUS = 30
MALICIOUS = 70
CORROBORATION_BONUS = 10


def combine(results: list[ProviderResult]) -> tuple[int | None, str]:
    """Return (score, verdict). Verdict is malicious/suspicious/clean/unknown."""
    scores = [r.score for r in results if r.status == "ok" and r.score is not None]
    if not scores:
        # Nothing scored. If someone looked and found nothing, that is "unknown",
        # not "clean": absence of reports is not proof of safety.
        return None, "unknown"

    overall = max(scores)
    if sum(1 for s in scores if s >= SUSPICIOUS) >= 2:
        overall = min(100, overall + CORROBORATION_BONUS)

    if overall >= MALICIOUS:
        verdict = "malicious"
    elif overall >= SUSPICIOUS:
        verdict = "suspicious"
    else:
        verdict = "clean"
    return overall, verdict
