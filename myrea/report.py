from __future__ import annotations
from datetime import datetime, timezone


def _fmt_ts(ts: int) -> str:
    if not ts:
        return "0 (not set)"
    try:
        return f"{ts} ({datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()})"
    except (OverflowError, OSError):
        return str(ts)


def render_markdown(r) -> str:
    lines: list[str] = []
    lines.append(f"# MyREA report — {r.file}\n")
    lines.append("## File\n")
    lines.append(f"- **SHA256:** `{r.sha256}`")
    lines.append(f"- **Size:** {r.file_size} bytes")
    lines.append(f"- **Arch:** {r.arch}")
    lines.append(f"- **Image base:** `0x{r.image_base:08x}`")
    lines.append(f"- **Entry point:** `0x{r.entrypoint_va:08x}`")
    lines.append(f"- **Compile timestamp:** {_fmt_ts(r.compile_timestamp)}")
    if r.timestamp_anomaly:
        lines.append(f"- **Timestamp anomaly:** `{r.timestamp_anomaly}`")
    lines.append(f"- **Signed:** {r.has_signature}")
    if r.has_overlay:
        lines.append(f"- **Overlay:** {r.overlay_size} bytes past last section")
    lines.append("")

    lines.append("## Sections\n")
    lines.append("| Name | RVA | Virt Size | Raw Size | Entropy | Flags |")
    lines.append("|------|-----|-----------|----------|---------|-------|")
    for s in r.sections:
        flags = ("X" if s.is_executable else "-") + ("W" if s.is_writable else "-")
        lines.append(
            f"| `{s.name}` | 0x{s.rva:08x} | 0x{s.virtual_size:x} | "
            f"0x{s.raw_size:x} | {s.entropy:.3f} | {flags} |"
        )
    lines.append("")

    if r.yara_matches:
        lines.append("## YARA matches\n")
        for m in r.yara_matches:
            desc = m.get("meta", {}).get("description", "")
            lines.append(f"- **{m['rule']}** — {desc}" if desc else f"- **{m['rule']}**")
            for s in m.get("strings", [])[:3]:
                lines.append(f"  - `{s['identifier']}` @ 0x{s['offset']:x}")
        lines.append("")
    lines.append("## Findings\n")
    if r.findings:
        for f in r.findings:
            lines.append(f"- {f}")
    else:
        lines.append("- *No findings.*")
    lines.append("")

    if r.imports:
        lines.append("## Imports\n")
        by_lib: dict[str, list[str]] = {}
        for imp in r.imports:
            by_lib.setdefault(imp.library, []).append(imp.function)
        for lib, funcs in by_lib.items():
            lines.append(f"- **{lib}** ({len(funcs)} symbols)")
        lines.append("")

    interesting = {k: v for k, v in r.strings.items() if k != "other" and v}
    if interesting:
        lines.append("## Interesting strings\n")
        for cat, items in interesting.items():
            lines.append(f"### {cat} ({len(items)})\n")
            for s in items[:25]:
                lines.append(f"- `{s}`")
            if len(items) > 25:
                lines.append(f"- *…and {len(items) - 25} more*")
            lines.append("")

    if r.errors:
        lines.append("## Warnings\n")
        for e in r.errors:
            lines.append(f"- {e}")
        lines.append("")

    return "\n".join(lines)
