#!/usr/bin/env python3
"""Regenerate docs/RULES.md from the rule registry (src/txwarden/rules.py).

    python scripts/gen_rules_doc.py            # write docs/RULES.md
    python scripts/gen_rules_doc.py --check    # exit 1 if the committed file is stale (CI)
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from txwarden.ruledocs import rules_markdown  # noqa: E402

TARGET = ROOT / "docs" / "RULES.md"


def main() -> int:
    text = rules_markdown()
    if "--check" in sys.argv[1:]:
        if not TARGET.exists() or TARGET.read_text() != text:
            print("docs/RULES.md is stale: run `python scripts/gen_rules_doc.py`", file=sys.stderr)
            return 1
        return 0
    TARGET.parent.mkdir(exist_ok=True)
    TARGET.write_text(text)
    print(f"wrote {TARGET.relative_to(ROOT)} ({text.count(chr(10))} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
