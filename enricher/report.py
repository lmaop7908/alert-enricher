"""Render enrichment results as text, JSON, or a self-contained HTML page."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .core import Enrichment

VERDICT_COLORS = {
    "malicious": "#c92a2a",
    "suspicious": "#e67700",
    "clean": "#2b8a3e",
    "unknown": "#5c5f66",
}


def explain(e: Enrichment) -> str:
    """One plain-English sentence on what the verdict means and what to do."""
    if e.note:
        return ""
    is_file = e.indicator.kind == "hash"
    thing = "file" if is_file else "indicator"
    if e.verdict == "malicious":
        action = "do not open or run it" if is_file else "block it and investigate"
        return f"Strong evidence this {thing} is malicious; {action}."
    if e.verdict == "suspicious":
        return (
            f"Some detections, but below the malicious threshold. This {thing} may be a "
            "false positive; review who flagged it before trusting it."
        )
    if e.verdict == "clean":
        if is_file:
            return (
                "Known file and no engine flagged it. Low risk, though a hash lookup "
                "cannot catch brand-new or modified malware."
            )
        return "Providers have data on this indicator and none of it points to abuse."
    if any(r.status == "error" for r in e.results):
        return "A lookup failed, so there is no verdict. Fix the error above and rerun."
    if any(r.status == "not_found" for r in e.results):
        meaning = f"No provider has a record of this {thing}. That means never seen, not safe."
        if e.local and e.local.signed_by:
            meaning += (
                f" It does carry a valid signature from {e.local.signed_by}, so it has not "
                "been changed since they signed it."
            )
        return meaning
    return f"No configured provider can check this {thing}, so there is no verdict."


def _to_dict(e: Enrichment) -> dict:
    return {
        "indicator": e.indicator.value or e.raw,
        "label": e.label,
        "source": e.source,
        "local": e.local.facts if e.local else [],
        "type": e.indicator.kind,
        "verdict": e.verdict,
        "score": e.score,
        "note": e.note,
        "meaning": explain(e),
        "providers": [
            {
                "provider": r.provider,
                "status": r.status,
                "score": r.score,
                "summary": r.summary,
                "facts": r.facts,
            }
            for r in e.results
        ],
    }


def as_json(items: list[Enrichment]) -> str:
    return json.dumps([_to_dict(e) for e in items], indent=2)


def as_text(items: list[Enrichment]) -> str:
    lines: list[str] = []
    for e in items:
        score = "n/a" if e.score is None else str(e.score)
        name = f"{e.label}  " if e.label else ""
        lines.append(f"{name}{e.indicator.value or e.raw}  [{e.indicator.kind}]")
        lines.append(f"  verdict: {e.verdict.upper()}  (score {score}/100)")
        if e.source:
            lines.append(f"  file: {e.source}")
        if e.local:
            lines.extend(f"      {fact}" for fact in e.local.facts)
        if e.note:
            lines.append(f"  note: {e.note}")
        for r in e.results:
            lines.append(f"  - {r.provider}: {r.status} - {r.summary}")
            lines.extend(f"      {fact}" for fact in r.facts)
        meaning = explain(e)
        if meaning:
            lines.append(f"  meaning: {meaning}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def as_html(items: list[Enrichment]) -> str:
    esc = html.escape
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = []
    for e in items:
        color = VERDICT_COLORS.get(e.verdict, VERDICT_COLORS["unknown"])
        score = "n/a" if e.score is None else str(e.score)
        detail = "<br>".join(
            f"<b>{esc(r.provider)}</b>: {esc(r.status)} - {esc(r.summary)}"
            + "".join(f"<br>&nbsp;&nbsp;{esc(fact)}" for fact in r.facts)
            for r in e.results
        ) or esc(e.note)
        meaning = explain(e)
        if meaning:
            detail += f"<br><i>{esc(meaning)}</i>"
        rows.append(
            f"<tr><td>{f'<b>{esc(e.label)}</b><br>' if e.label else ''}"
            f"<code>{esc(e.indicator.value or e.raw)}</code>"
            f"{f'<br>{esc(e.source)}' if e.source else ''}"
            f"{''.join(f'<br>{esc(fact)}' for fact in e.local.facts) if e.local else ''}</td>"
            f"<td>{esc(e.indicator.kind)}</td>"
            f'<td style="color:{color};font-weight:700">{esc(e.verdict.upper())}</td>'
            f"<td>{esc(score)}</td><td>{detail}</td></tr>"
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Enrichment report</title>
<style>
body{{font:15px/1.5 system-ui,sans-serif;margin:32px;color:#1c1c1a}}
table{{border-collapse:collapse;width:100%}}
th,td{{border-bottom:1px solid #ddd;padding:8px 10px;text-align:left;vertical-align:top}}
th{{background:#f4f4f1}} code{{font-size:13px}}
</style></head><body>
<h1>Indicator enrichment report</h1>
<p>Generated {esc(generated)}. Scores are 0-100; "unknown" means no provider had data, not that the indicator is safe.</p>
<table><tr><th>Indicator</th><th>Type</th><th>Verdict</th><th>Score</th><th>Details</th></tr>
{''.join(rows)}
</table></body></html>
"""
