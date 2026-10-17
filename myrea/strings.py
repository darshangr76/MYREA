from __future__ import annotations
import re
import string
from .models import SectionInfo


MIN_STRING_LEN = 4

_PRINTABLE = set(string.printable) - set("\t\n\r\x0b\x0c")

_URL_RE = re.compile(rb"(?:https?|ftp)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,}")
_IPV4_RE = re.compile(
    rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

def _looks_like_real_ip(s: str) -> bool:
    """Reject things like '1.1.0.14' or '3.2.1.0' — versions masquerading as IPs.
    A real public IP typically has at least one octet >= 20."""
    try:
        parts = [int(x) for x in s.split(".")]
    except ValueError:
        return False
    if len(parts) != 4 or any(p > 255 for p in parts):
        return False
    return max(parts) >= 20
_REGISTRY_RE = re.compile(
    rb"(?:SOFTWARE|SYSTEM|HKEY_|HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)"
    rb"[\\A-Za-z0-9 _\-./]{4,}"
)
_SUSPICIOUS_TOKENS = [
    b"cmd.exe", b"powershell", b"pwsh", b"-enc", b"-EncodedCommand",
    b"WScript.Shell", b"WMI", b"Win32_Process", b"rundll32",
    b"regsvr32", b"schtasks", b"certutil", b"bitsadmin",
        b".onion", b"bitcoin", b"ransom", b"encrypt", b"decrypt",
    b"MZ", b"This program cannot be run in DOS mode",
]


def _extract_ascii(data: bytes) -> list[str]:
    out: list[str] = []
    buf = bytearray()
    for b in data:
        if chr(b) in _PRINTABLE:
            buf.append(b)
        else:
            if len(buf) >= MIN_STRING_LEN:
                out.append(buf.decode("ascii", errors="replace"))
            buf.clear()
    if len(buf) >= MIN_STRING_LEN:
        out.append(buf.decode("ascii", errors="replace"))
    return out


def _extract_utf16le(data: bytes) -> list[str]:
    out: list[str] = []
    # Walk pairs; a wide string is printable-ASCII chars followed by 0x00.
    buf: list[str] = []
    i = 0
    while i + 1 < len(data):
        lo, hi = data[i], data[i + 1]
        if hi == 0 and chr(lo) in _PRINTABLE:
            buf.append(chr(lo))
        else:
            if len(buf) >= MIN_STRING_LEN:
                out.append("".join(buf))
            buf.clear()
        i += 2
    if len(buf) >= MIN_STRING_LEN:
        out.append("".join(buf))
    return out


def _categorize(strings: list[str], raw_blob: bytes) -> dict[str, list[str]]:
    cats: dict[str, list[str]] = {
        "urls": [], "ipv4": [], "registry": [],
        "suspicious": [], "other": [],
    }
    seen = set()
    for s in strings:
        if s in seen or len(s) < MIN_STRING_LEN:
            continue
        seen.add(s)
        sbytes = s.encode("ascii", errors="replace")
        if _URL_RE.search(sbytes):
            cats["urls"].append(s)
        elif _IPV4_RE.fullmatch(sbytes) and _looks_like_real_ip(s):
            cats["ipv4"].append(s)
        elif _REGISTRY_RE.search(sbytes):
            cats["registry"].append(s)
        elif any(tok in sbytes for tok in _SUSPICIOUS_TOKENS):
            cats["suspicious"].append(s)
        else:
            cats["other"].append(s)
    return cats


def extract_strings(sections: list[SectionInfo], binary) -> dict[str, list[str]]:
    """Extract ASCII + UTF-16LE strings from all sections. Dedupe and categorize."""
    all_ascii: list[str] = []
    all_utf16: list[str] = []
    raw_all = bytearray()

    for sec in sections:
        lief_sec = next(
            (s for s in binary.sections if s.virtual_address == sec.rva), None
        )
        if lief_sec is None:
            continue
        raw = bytes(lief_sec.content)
        raw_all.extend(raw)
        all_ascii.extend(_extract_ascii(raw))
        all_utf16.extend(_extract_utf16le(raw))

    combined = all_ascii + all_utf16
    return _categorize(combined, bytes(raw_all))
