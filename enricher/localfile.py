"""Offline checks on a local file: real type, digital signature, download origin.

Nothing here touches the network, so these still describe a file whose hash
no provider has seen. Signature and origin checks are Windows-only.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

PE_EXTS = {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".com", ".drv", ".efi", ".mui"}
# (magic bytes, description, short kind)
MAGIC = [
    (b"MZ", "Windows executable (PE)", "pe"),
    (b"\x7fELF", "Linux executable (ELF)", "elf"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut (LNK)", "lnk"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 container (MSI installer or legacy Office)", "ole"),
    (b"MSCF", "Microsoft cabinet archive", "cab"),
    (b"PK\x03\x04", "ZIP container (zip, Office document, JAR, APK)", "zip"),
    (b"Rar!", "RAR archive", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "7z"),
    (b"\x1f\x8b", "gzip archive", "gzip"),
    (b"%PDF", "PDF document", "pdf"),
    (b"\x89PNG", "PNG image", "png"),
    (b"\xff\xd8\xff", "JPEG image", "jpeg"),
    (b"GIF8", "GIF image", "gif"),
    (b"#!", "script with interpreter line", "script"),
]
# Kinds that run code when opened, whatever the extension claims.
RUNNABLE = {"pe": PE_EXTS, "elf": None, "lnk": {".lnk"}}
SIGNABLE_KINDS = {"pe", "ole", "cab"}
SIGNABLE_EXTS = {".ps1", ".psm1", ".msi", ".msix", ".appx", ".cat", ".vbs", ".js"}
DECOY_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".mp4", ".zip"}
ZONES = {
    "0": "this computer",
    "1": "the local intranet",
    "2": "a trusted site",
    "3": "the internet",
    "4": "a restricted site",
}
SIGNATURE_SCRIPT = (
    "$s = Get-AuthenticodeSignature -LiteralPath $env:ENRICHER_FILE; "
    '[pscustomobject]@{status="$($s.Status)"; kind="$($s.SignatureType)"; '
    "subject=$s.SignerCertificate.Subject; issuer=$s.SignerCertificate.Issuer} "
    "| ConvertTo-Json -Compress"
)


@dataclass
class LocalFile:
    facts: list[str] = field(default_factory=list)
    signed_by: str = ""  # set only when the signature is valid


def sniff(head: bytes) -> tuple[str, str]:
    """Identify a file from its first bytes. Returns (description, kind)."""
    for magic, description, kind in MAGIC:
        if head.startswith(magic):
            return description, kind
    if not head:
        return "empty file", "empty"
    if b"\x00" not in head:
        try:
            head.decode("utf-8")
            return "text", "text"
        except UnicodeDecodeError:
            pass
    return "unrecognized binary data", "binary"


def type_facts(name: str, head: bytes) -> tuple[list[str], str]:
    """Real type from content, plus warnings when the name disagrees with it."""
    description, kind = sniff(head)
    facts = [f"real type: {description}"]
    suffixes = [s.lower() for s in Path(name).suffixes]
    ext = suffixes[-1] if suffixes else ""

    if kind in RUNNABLE and RUNNABLE[kind] is not None and ext not in RUNNABLE[kind]:
        facts.append(
            f"warning: content is a {description} but the extension is "
            f"'{ext or '(none)'}'; it may be disguised"
        )
    if len(suffixes) >= 2 and ext in PE_EXTS | {".lnk"} and suffixes[-2] in DECOY_EXTS:
        facts.append(
            f"warning: double extension '{suffixes[-2]}{ext}' is a common trick to make "
            "a program look like a document"
        )
    return facts, kind


def _common_name(distinguished_name: str | None) -> str:
    match = re.search(r'CN="([^"]+)"|CN=([^,]+)', distinguished_name or "")
    return (match.group(1) or match.group(2)).strip() if match else ""


def signature_fact(status: str, kind: str, subject: str | None, issuer: str | None) -> tuple[str, str]:
    """Turn Get-AuthenticodeSignature output into (fact, signer-if-valid)."""
    signer, authority = _common_name(subject), _common_name(issuer)
    if status == "Valid":
        via = " via Windows catalog" if kind == "Catalog" else ""
        issued = f", certificate issued by {authority}" if authority else ""
        return f"signature: valid, signed by {signer or 'unknown signer'}{via}{issued}", signer
    if status == "NotSigned":
        return "signature: not signed", ""
    if status == "HashMismatch":
        who = f" by {signer}" if signer else ""
        return f"warning: signature is INVALID; the file was changed after it was signed{who}", ""
    who = f" (certificate names {signer})" if signer else ""
    return f"warning: signature is not trusted: {status}{who}", ""


def check_signature(path: Path, run=subprocess.run) -> tuple[str, str]:
    """Ask Windows whether the file's Authenticode signature is valid."""
    try:
        proc = run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", SIGNATURE_SCRIPT],
            # The path travels in the environment so it is never parsed as code.
            env={**os.environ, "ENRICHER_FILE": str(path)},
            capture_output=True,
            text=True,
            timeout=120,
        )
        data = json.loads(proc.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        return "signature: could not be checked", ""
    return signature_fact(
        data.get("status", ""), data.get("kind", ""), data.get("subject"), data.get("issuer")
    )


def origin_fact(zone_identifier: str) -> str:
    """Describe the 'Mark of the Web' Windows attaches to downloaded files."""
    fields = dict(
        line.split("=", 1) for line in zone_identifier.splitlines() if "=" in line
    )
    clean = lambda url: "".join(c for c in url.strip() if c.isprintable())[:200]  # noqa: E731
    zone = ZONES.get(fields.get("ZoneId", "").strip(), "an unknown zone")
    fact = f"origin: downloaded from {zone}"
    if fields.get("HostUrl"):
        fact += f" - {clean(fields['HostUrl'])}"
    if fields.get("ReferrerUrl"):
        fact += f" (linked from {clean(fields['ReferrerUrl'])})"
    return fact


def read_origin(path: Path) -> str:
    try:
        with open(f"{path}:Zone.Identifier", encoding="utf-8", errors="replace") as fh:
            return origin_fact(fh.read())
    except OSError:
        return "origin: no download mark (made locally, unpacked from an archive, or mark removed)"


def inspect_file(path: Path, platform: str = sys.platform) -> LocalFile:
    """Run every local check that applies to this file on this platform."""
    with open(path, "rb") as fh:
        head = fh.read(4096)
    info = LocalFile()
    info.facts, kind = type_facts(path.name, head)

    if platform == "win32":
        if kind in SIGNABLE_KINDS or path.suffix.lower() in SIGNABLE_EXTS:
            fact, info.signed_by = check_signature(path)
            info.facts.append(fact)
        info.facts.append(read_origin(path))
    return info
