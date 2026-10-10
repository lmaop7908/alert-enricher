"""Indicator parsing: classify raw strings as IP, domain, URL, or file hash."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
HEX_RE = re.compile(r"^[a-f0-9]+$")


@dataclass(frozen=True)
class Indicator:
    value: str  # normalized (refanged, lowercased where safe)
    kind: str  # "ip" | "domain" | "url" | "hash" | "unknown"
    subtype: str = ""  # e.g. "md5", "ipv4", "ipv6"

    @property
    def is_public_ip(self) -> bool:
        if self.kind != "ip":
            return False
        return ipaddress.ip_address(self.value).is_global


def refang(raw: str) -> str:
    """Undo common 'defanging' used when sharing IOCs safely (hxxp, [.])."""
    value = raw.strip()
    value = re.sub(r"^hxxp", "http", value, flags=re.IGNORECASE)
    value = value.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    value = value.replace("[://]", "://")
    return value


def classify(raw: str) -> Indicator:
    """Classify a raw indicator string."""
    value = refang(raw)
    if not value:
        return Indicator(value="", kind="unknown")

    # URL
    if re.match(r"^[a-z][a-z0-9+.-]*://", value, flags=re.IGNORECASE):
        return Indicator(value=value, kind="url")

    # IP
    try:
        ip = ipaddress.ip_address(value)
        return Indicator(value=str(ip), kind="ip", subtype=f"ipv{ip.version}")
    except ValueError:
        pass

    # Hash
    lowered = value.lower()
    if len(lowered) in HASH_LENGTHS and HEX_RE.match(lowered):
        return Indicator(value=lowered, kind="hash", subtype=HASH_LENGTHS[len(lowered)])

    # Domain
    if DOMAIN_RE.match(lowered):
        return Indicator(value=lowered, kind="domain")

    return Indicator(value=value, kind="unknown")


def human_size(num_bytes: int) -> str:
    """Format a byte count for display, e.g. 1536 -> '1.5 KB'."""
    size = float(num_bytes)
    for unit in ("bytes", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)} bytes" if unit == "bytes" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{num_bytes} bytes"  # pragma: no cover


def hash_file(path, chunk_size: int = 1024 * 1024) -> str:
    """SHA-256 of a local file, read in chunks so large files don't fill memory.

    Only this hash is ever sent to a provider; the file itself stays local.
    """
    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            sha.update(chunk)
    return sha.hexdigest()
