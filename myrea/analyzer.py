from __future__ import annotations
import os
from .pe_parser import parse_pe
from .disassembler import (
    init_capstone,
    disassemble_entrypoint,
    disassemble_section,
)
from .models import AnalysisResult
from .heuristics import run_heuristics
from .strings import extract_strings
from .file_meta import collect as collect_meta


def analyze(filepath: str, full_disasm: bool = False) -> AnalysisResult:
    binary, is_64bit, ep_rva, image_base, sections, imports = parse_pe(filepath)

    result = AnalysisResult(
        file=os.path.basename(filepath),
        arch="x86_64" if is_64bit else "x86",
        is_64bit=is_64bit,
        entrypoint_va=image_base + ep_rva,
        image_base=image_base,
        sections=sections,
        imports=imports,
    )

    md = init_capstone(is_64bit)

    try:
        result.entrypoint_disasm = disassemble_entrypoint(
            md, binary, sections, image_base, ep_rva
        )
    except Exception as e:
        result.errors.append(f"entrypoint disasm failed: {e}")

    if full_disasm:
        total = 0
        for sec in sections:
            if not sec.is_executable:
                continue
            try:
                insns = disassemble_section(md, binary, sec, image_base)
                total += len(insns)
            except Exception as e:
                result.errors.append(f"disasm {sec.name} failed: {e}")
        result.total_instructions = total
    else:
        result.total_instructions = len(result.entrypoint_disasm)

    try:
        meta = collect_meta(filepath, binary)
        for k, v in meta.items():
            setattr(result, k, v)
    except Exception as e:
        result.errors.append(f"file_meta failed: {e}")
    result.findings = run_heuristics(sections, imports)
    try:
        result.strings = extract_strings(sections, binary)
    except Exception as e:
        result.errors.append(f"string extraction failed: {e}")
    return result
