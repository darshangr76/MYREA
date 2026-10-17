from __future__ import annotations
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CsError
from .models import Instruction, SectionInfo


def init_capstone(is_64bit: bool) -> Cs:
    md = Cs(CS_ARCH_X86, CS_MODE_64 if is_64bit else CS_MODE_32)
    md.detail = False
    md.skipdata = True
    return md


def _to_instructions(md, code, base_va, count=0):
    out = []
    try:
        for insn in md.disasm(code, base_va, count=count):
            out.append(Instruction(
                address=insn.address,
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
                bytes_hex=insn.bytes.hex(),
                size=insn.size,
            ))
    except CsError:
        pass
    return out


def disassemble_entrypoint(md, binary, sections, image_base, entrypoint_rva, max_insns=80):
    from .pe_parser import find_section_for_rva
    sec = find_section_for_rva(sections, entrypoint_rva)
    if sec is None:
        return []

    lief_sec = next(
        (s for s in binary.sections if s.virtual_address == sec.rva), None
    )
    if lief_sec is None:
        return []

    offset = entrypoint_rva - sec.rva
    code = bytes(lief_sec.content)[offset:offset + 4096]
    va = image_base + entrypoint_rva
    return _to_instructions(md, code, va, count=max_insns)


def disassemble_section(md, binary, section, image_base):
    lief_sec = next(
        (s for s in binary.sections if s.virtual_address == section.rva), None
    )
    if lief_sec is None:
        return []
    code = bytes(lief_sec.content)
    va = image_base + section.rva
    return _to_instructions(md, code, va)
