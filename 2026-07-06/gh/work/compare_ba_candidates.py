import difflib
import json
from pathlib import Path


root = Path(r"C:\Users\design\Documents\Codex\2026-07-06\gh\work")
aa = json.loads((root / "trackaa.selected.json").read_text(encoding="utf-8"))
ab = json.loads((root / "trackab.selected.json").read_text(encoding="utf-8"))
ba = json.loads((root / "trackba.selected.json").read_text(encoding="utf-8"))


def by_name(doc):
    return {f["name"]: f for f in doc["functions"] if f}


aa_n = by_name(aa)
ab_n = by_name(ab)
ba_n = by_name(ba)

pairs = [
    ("sub_4715B0", "sub_471560", "sub_47B6C0"),
    ("sub_4720A0", "sub_472050", "sub_47C280"),
    ("sub_476880", "sub_476840", "sub_481320"),
    ("sub_4D56B3", None, "sub_4E5BF0"),
    ("sub_4DD64E", None, "sub_4EDBE9"),
]


def texts(f):
    return [x["text"] for x in f["insns"]]


def mnem(line):
    return line.strip().split(None, 1)[0] if line.strip() else ""


def show_diff(label_a, a_lines, label_b, b_lines, max_blocks=8):
    sm = difflib.SequenceMatcher(None, a_lines, b_lines)
    blocks = [op for op in sm.get_opcodes() if op[0] != "equal"]
    print(f"  {label_a} vs {label_b}: ratio={sm.ratio():.3f} blocks={len(blocks)}")
    for tag, i1, i2, j1, j2 in blocks[:max_blocks]:
        print(f"    {tag} {label_a}[{i1}:{i2}] {label_b}[{j1}:{j2}]")
        for line in a_lines[i1:min(i2, i1 + 4)]:
            print(f"      - {line}")
        for line in b_lines[j1:min(j2, j1 + 4)]:
            print(f"      + {line}")


for old_name, new_name, ba_name in pairs:
    old = aa_n[old_name]
    cand = ba_n[ba_name]
    print(f"=== {old_name} -> {new_name or 'removed?'} ; ba {ba_name} ===")
    old_lines = texts(old)
    ba_lines = texts(cand)
    show_diff("aa_old", old_lines, "ba", ba_lines, 5)
    if new_name:
        new_lines = texts(ab_n[new_name])
        show_diff("ab_new", new_lines, "ba", ba_lines, 5)
        show_diff("aa_old_mnem", [mnem(x) for x in old_lines], "ab_new_mnem", [mnem(x) for x in new_lines], 5)
    print(f"  ba file range: 0x{cand['insns'][0]['off']:X}-0x{cand['insns'][-1]['off']:X}")
    print()
