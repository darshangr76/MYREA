from __future__ import annotations
import lief
from .models import SectionInfo, ImportInfo


def parse_pe(filepath: str):
    binary = lief.parse(filepath)
    if binary is None or not isinstance(binary, lief.PE.Binary):
        raise ValueError(f"Not a valid PE file: {filepath}")

    # LIEF 1.0 removed MACHINE_TYPES; use PE spec constants directly.
    # AMD64=0x8664, IA64=0x0200, ARM64=0xAA64
    _MACHINE_64BIT = {0x8664, 0x0200, 0xAA64}
    _m = binary.header.machine
    if hasattr(_m, "value"):
        _m = _m.value
    is_64bit = int(_m) in _MACHINE_64BIT
    entrypoint_rva = binary.optional_header.addressof_entrypoint
    image_base = binary.optional_header.imagebase

    sections: list[SectionInfo] = []
    for section in binary.sections:
        sections.append(SectionInfo(
            name=section.name,
            rva=section.virtual_address,
            virtual_size=section.virtual_size,
            raw_size=section.size,
            entropy=round(section.entropy, 4),
            characteristics=int(section.characteristics),
            is_executable=section.has_characteristic(
                lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
            ),
            is_writable=section.has_characteristic(
                lief.PE.Section.CHARACTERISTICS.MEM_WRITE
            ),
        ))

    imports: list[ImportInfo] = []
    for lib in binary.imports:
        for entry in lib.entries:
            imports.append(ImportInfo(
                library=lib.name,
                function=entry.name if entry.name else f"ordinal_{entry.ordinal}",
                iat_address=entry.iat_address,
            ))

    return binary, is_64bit, entrypoint_rva, image_base, sections, imports


def find_section_for_rva(sections: list[SectionInfo], rva: int) -> SectionInfo | None:
    for sec in sections:
        if sec.rva <= rva < sec.rva + max(sec.virtual_size, sec.raw_size):
            return sec
    return None
