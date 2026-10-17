from __future__ import annotations
import argparse
import sys
from .analyzer import analyze
from .report import render_markdown


def _fmt_insn(insn) -> str:
    return f"  0x{insn.address:08x}  {insn.mnemonic:<8} {insn.op_str}"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="myrea",
        description="MyREA Phase 1 - Static PE analyzer (LIEF + Capstone)",
    )
    p.add_argument("file", help="Path to a PE file")
    p.add_argument("--full", action="store_true",
                   help="Disassemble all executable sections")
    p.add_argument("--json", action="store_true",
                   help="Emit JSON instead of human-readable output")
    p.add_argument("--report", metavar="PATH",
                   help="Write a Markdown triage report to PATH")
    args = p.parse_args(argv)

    try:
        result = analyze(args.file, full_disasm=args.full)
    except Exception as e:
        print(f"[!] Analysis failed: {e}", file=sys.stderr)
        return 1

    if args.report:
        with open(args.report, "w") as f:
            f.write(render_markdown(result))
        print(f"[+] Wrote report to {args.report}")

    if args.json:
        print(result.to_json())
        return 0

    print(f"File:        {result.file}")
    print(f"Arch:        {result.arch}")
    print(f"Image base:  0x{result.image_base:08x}")
    print(f"Entry point: 0x{result.entrypoint_va:08x}")
    print(f"SHA256:      {result.sha256}")
    print(f"File size:   {result.file_size} bytes")
    print(f"Compiled:    {result.compile_timestamp}"
          + (f"  [!] {result.timestamp_anomaly}" if result.timestamp_anomaly else ""))
    print(f"Signed:      {result.has_signature}")
    if result.has_overlay:
        print(f"Overlay:     {result.overlay_size} bytes past last section")
    print()

    print(f"Sections ({len(result.sections)}):")
    for s in result.sections:
        flags = []
        if s.is_executable: flags.append("X")
        if s.is_writable:   flags.append("W")
        print(f"  {s.name:<10} rva=0x{s.rva:08x} vsize=0x{s.virtual_size:<6x} "
              f"entropy={s.entropy:<6.3f} [{'|'.join(flags) or '-'}]")
    print()

    print(f"Imports ({len(result.imports)}):")
    by_lib = {}
    for imp in result.imports:
        by_lib.setdefault(imp.library, []).append(imp.function)
    for lib, funcs in by_lib.items():
        print(f"  {lib} ({len(funcs)} symbols)")
    print()

    print(f"Entry-point disassembly ({len(result.entrypoint_disasm)} insns):")
    for insn in result.entrypoint_disasm:
        print(_fmt_insn(insn))

    if result.findings:
        print()
        print(f"Findings ({len(result.findings)}):")
        for f in result.findings:
            print(f"  [*] {f}")

    if result.strings:
        interesting = {k: v for k, v in result.strings.items()
                       if k != "other" and v}
        if interesting:
            print()
            print("Interesting strings:")
            for cat, items in interesting.items():
                print(f"  {cat} ({len(items)}):")
                for s in items[:15]:
                    print(f"    {s!r}")
                if len(items) > 15:
                    print(f"    ... and {len(items) - 15} more")

    if result.errors:
        print()
        print("Warnings:")
        for e in result.errors:
            print(f"  [!] {e}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
