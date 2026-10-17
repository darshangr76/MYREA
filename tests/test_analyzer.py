import os
import pytest
from myrea.analyzer import analyze

# Drop any small .exe/.dll into tests/samples/ to enable the test.
SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "samples")
SAMPLE = None
if os.path.isdir(SAMPLE_DIR):
    for name in os.listdir(SAMPLE_DIR):
        if name.lower().endswith((".exe", ".dll")):
            SAMPLE = os.path.join(SAMPLE_DIR, name)
            break


@pytest.mark.skipif(SAMPLE is None, reason="No PE sample in tests/samples/")
def test_analyze_real_pe():
    result = analyze(SAMPLE)
    assert result.arch in ("x86", "x86_64")
    assert result.entrypoint_va >= result.image_base
    assert len(result.sections) > 0
    assert result.entrypoint_disasm, "entrypoint should disassemble to at least one insn"
