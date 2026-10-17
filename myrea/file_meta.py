from __future__ import annotations
import hashlib
import os
import time


# Timestamps before 2000 or after "now + 1 day" are almost always forged.
_MIN_SANE = 946684800   # 2000-01-01
_FUTURE_GRACE = 86400


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def timestamp_anomaly(ts: int) -> str | None:
    if ts == 0:
        return "zero"
    now = int(time.time())
    if ts < _MIN_SANE:
        return "pre_2000"
    if ts > now + _FUTURE_GRACE:
        return "future"
    return None


def check_overlay(binary) -> tuple[bool, int]:
    """Return (has_overlay, overlay_size). Overlay = bytes past the last section's raw end."""
    try:
        last_end = 0
        for sec in binary.sections:
            end = sec.offset + sec.size
            if end > last_end:
                last_end = end
    except Exception:
        return False, 0

    try:
        file_size = os.path.getsize(binary.name) if binary.name else 0
    except Exception:
        file_size = 0

    if file_size == 0:
        return False, 0
    if last_end and file_size > last_end:
        return True, file_size - last_end
    return False, 0


def has_signature(binary) -> bool:
    try:
        return bool(binary.has_signatures)
    except Exception:
        return False


def collect(filepath: str, binary) -> dict:
    sha = sha256_file(filepath)
    size = os.path.getsize(filepath)
    ts = int(binary.header.time_date_stamps)
    anomaly = timestamp_anomaly(ts)
    has_ov, ov_size = check_overlay(binary)
    signed = has_signature(binary)
    return {
        "sha256": sha,
        "file_size": size,
        "compile_timestamp": ts,
        "timestamp_anomaly": anomaly,
        "has_overlay": has_ov,
        "overlay_size": ov_size,
        "has_signature": signed,
    }
