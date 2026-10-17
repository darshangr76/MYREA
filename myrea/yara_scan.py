from __future__ import annotations
import os
from typing import Any


try:
    import yara
    _HAS_YARA = True
except ImportError:
    _HAS_YARA = False


RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")


def _compile_rules(rules_dir: str):
    if not _HAS_YARA:
        return None
    if not os.path.isdir(rules_dir):
        return None

    paths = {}
    for name in sorted(os.listdir(rules_dir)):
        if name.endswith((".yar", ".yara")):
            paths[name] = os.path.join(rules_dir, name)
    if not paths:
        return None
    return yara.compile(filepaths=paths)


def scan_file(filepath: str) -> list[dict[str, Any]]:
    """Run all rules against the raw file bytes. Returns list of match dicts."""
    if not _HAS_YARA:
        return []

    rules = _compile_rules(RULES_DIR)
    if rules is None:
        return []

    matches = rules.match(filepath)
    out: list[dict[str, Any]] = []
    for m in matches:
        out.append({
            "rule": m.rule,
            "namespace": m.namespace,
            "tags": list(m.tags),
            "meta": dict(m.meta),
            "strings": [
                {"identifier": s.identifier, "offset": s.instances[0].offset if s.instances else 0}
                for s in m.strings
            ],
        })
    return out
