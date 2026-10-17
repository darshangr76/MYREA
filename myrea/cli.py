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
    p.add_argument("file", nargs="?", help="Path to a PE file")
    p.add_argument("--dir", metavar="DIR",
                   help="Scan every PE in DIR (batch triage mode)")
    p.add_argument("--full", action="store_true",
                   help="Disassemble all executable sections")
    p.add_argument("--json", action="store_true",
                   help="Emit JSON instead of human-readable output")
    p.add_argument("--report", metavar="PATH",
                   help="Write a Markdown triage report to PATH")
    p.add_argument("--quiet", action="store_true",
                   help="Suppress entry-point disassembly output")
    p.add_argument("--no-disasm", action="store_true",
                   help="Skip disassembly entirely (faster batch runs)")
    args = p.parse_args(argv)

    if args.dir:
        return _scan_dir(args)

    if not args.file:
        p.error("either a file or --dir is required")

    try:
        result = analyze(args.file, full_disasm=args.full, no_disasm=args.no_disasm)
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

    if not args.quiet and not args.no_disasm:
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


def _scan_dir(args) -> int:
    import os
    from .analyzer import analyze as _analyze

    target = args.dir
    if not os.path.isdir(target):
        print(f"[!] Not a directory: {target}", file=sys.stderr)
        return 1

    pe_exts = (".exe", ".dll", ".sys", ".scr")
    paths = sorted(
        os.path.join(target, name)
        for name in os.listdir(target)
        if name.lower().endswith(pe_exts)
    )
    if not paths:
        print(f"[!] No PE files in {target}", file=sys.stderr)
        return 1

    print(f"Scanning {len(paths)} file(s) in {target}\n")
    print(f"{'File':<30} {'Arch':<8} {'Findings':>8}  {'Strong':>6}  {'YARA':>5}")
    print("-" * 65)

    rows = []
    for path in paths:
        try:
            r = _analyze(path, full_disasm=False, no_disasm=True)
            strong = sum(1 for f in r.findings if "[strong]" in f)
            yara = len(r.yara_matches)
            rows.append((os.path.basename(path), r.arch, len(r.findings), strong, yara))
        except Exception as e:
            rows.append((os.path.basename(path), "ERR", 0, 0, 0))
            print(f"[!] {path}: {e}", file=sys.stderr)

    rows.sort(key=lambda t: (t[3], t[4], t[2]), reverse=True)
    for name, arch, n_findings, strong, yara in rows:
        print(f"{name:<30} {arch:<8} {n_findings:>8}  {strong:>6}  {yara:>5}")

    return 0



if __name__ == "__main__":
    raise SystemExit(main())
