from __future__ import annotations
from dataclasses import dataclass, field, asdict
import json


@dataclass
class SectionInfo:
    name: str
    rva: int
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: int
    is_executable: bool
    is_writable: bool


@dataclass
class ImportInfo:
    library: str
    function: str
    iat_address: int


@dataclass
class Instruction:
    address: int
    mnemonic: str
    op_str: str
    bytes_hex: str
    size: int


@dataclass
class AnalysisResult:
    file: str
    arch: str
    is_64bit: bool
    entrypoint_va: int
    image_base: int
    sections: list[SectionInfo] = field(default_factory=list)
    imports: list[ImportInfo] = field(default_factory=list)
    entrypoint_disasm: list[Instruction] = field(default_factory=list)
    total_instructions: int = 0
    errors: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    strings: dict[str, list[str]] = field(default_factory=dict)
    sha256: str = ""
    file_size: int = 0
    compile_timestamp: int = 0
    timestamp_anomaly: str | None = None
    has_overlay: bool = False
    overlay_size: int = 0
    has_signature: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)
