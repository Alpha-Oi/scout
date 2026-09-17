#!/usr/bin/env python3
"""Create cross-platform skill adapters pointing to SKILL.md."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "SKILL.md"

ADAPTERS = [
    ROOT / ".claude/skills/scout/SKILL.md",
    ROOT / ".agents/skills/scout/SKILL.md",
    ROOT / ".cursor/skills/scout/SKILL.md",
]


def link_or_copy(src: Path, dst: Path) -> str:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists() or dst.is_symlink():
        dst.unlink()
    try:
        rel = src.relative_to(dst.parent)
        dst.symlink_to(rel)
        return "symlink " + str(dst.relative_to(ROOT))
    except (OSError, NotImplementedError):
        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        return "copy    " + str(dst.relative_to(ROOT))


def main() -> None:
    for dst in ADAPTERS:
        print(link_or_copy(SKILL, dst))
    print("done")


if __name__ == "__main__":
    main()
