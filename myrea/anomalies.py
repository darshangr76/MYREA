from __future__ import annotations


MIN_IMPORT_COUNT = 5
MAX_IMPORT_COUNT = 500
HIGH_ENTROPY_THRESHOLD = 7.0
OVERLAY_THRESHOLD = 10240   # 10 KB


def check_anomalies(result) -> list[str]:
    """Consolidated PE anomaly checks. Returns a list of finding strings."""
    out: list[str] = []

    if result.has_overlay and result.overlay_size >= OVERLAY_THRESHOLD:
        out.append(
            f"[anomaly] Large overlay: {result.overlay_size} bytes past last section"
        )

    n_imports = len(result.imports)
    if n_imports == 0:
        out.append("[anomaly] No imports (statically linked or obfuscated)")
    elif n_imports < MIN_IMPORT_COUNT:
        out.append(f"[anomaly] Unusually few imports: {n_imports}")
    elif n_imports > MAX_IMPORT_COUNT:
        out.append(f"[anomaly] Unusually many imports: {n_imports}")

    for sec in result.sections:
        if sec.virtual_size == 0 or sec.name.lower() == ".bss":
            continue
        if sec.raw_size == 0 and sec.virtual_size > 0x1000:
            out.append(
                f"[anomaly] Section {sec.name} has 0 raw bytes but "
                f"0x{sec.virtual_size:x} virtual"
            )
        elif sec.raw_size and sec.raw_size < sec.virtual_size * 0.25:
            out.append(
                f"[anomaly] Section {sec.name} raw={sec.raw_size} << virt={sec.virtual_size}"
            )

    for sec in result.sections:
        if sec.is_executable and sec.entropy >= HIGH_ENTROPY_THRESHOLD:
            out.append(
                f"[anomaly] High-entropy code section: {sec.name} ({sec.entropy:.2f})"
            )

    if result.timestamp_anomaly:
        out.append(f"[anomaly] Compile timestamp anomaly: {result.timestamp_anomaly}")

    if not result.has_signature:
        out.append("[anomaly] Unsigned")

    return out
