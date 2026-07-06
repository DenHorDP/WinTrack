import difflib
import json
from pathlib import Path


root = Path(r"C:\Users\design\Documents\Codex\2026-07-06\gh\work")
aa = json.loads((root / "trackaa.selected.json").read_text(encoding="utf-8"))
ab = json.loads((root / "trackab.selected.json").read_text(encoding="utf-8"))

pairs = [
    ("sub_41C870", "sub_41C8C0"),
    ("sub_43C380", "sub_43C2F0"),
    ("sub_43D390", "sub_43D300"),
    ("sub_4715B0", "sub_471560"),
    ("sub_4720A0", "sub_472050"),
    ("sub_476880", "sub_476840"),
    ("sub_497330", "sub_4972C0"),
    ("sub_4ADC00", "sub_4ADBB0"),
    ("_memcpy", "_memcpy"),
    ("_memcpy_0", "_memcpy_0"),
]


def by_name(doc):
    return {f["name"]: f for f in doc["functions"] if f}


def strip_operands(text):
    return text.split(None, 1)[0] if text.strip() else ""


def summarize(a, b):
    a_text = [x["text"] for x in a["insns"]]
    b_text = [x["text"] for x in b["insns"]]
    a_mnem = [strip_operands(x) for x in a_text]
    b_mnem = [strip_operands(x) for x in b_text]
    sm_text = difflib.SequenceMatcher(None, a_text, b_text)
    sm_mnem = difflib.SequenceMatcher(None, a_mnem, b_mnem)
    opcodes = sm_text.get_opcodes()
    blocks = [op for op in opcodes if op[0] != "equal"]
    return {
        "aa": a["name"],
        "ab": b["name"],
        "aa_insns": len(a_text),
        "ab_insns": len(b_text),
        "text_ratio": sm_text.ratio(),
        "mnem_ratio": sm_mnem.ratio(),
        "blocks": blocks[:8],
        "a_text": a_text,
        "b_text": b_text,
    }


aa_map = by_name(aa)
ab_map = by_name(ab)
for left, right in pairs:
    s = summarize(aa_map[left], ab_map[right])
    print(
        f"{left} -> {right}: insns {s['aa_insns']}->{s['ab_insns']} "
        f"text={s['text_ratio']:.3f} mnemonic={s['mnem_ratio']:.3f} "
        f"diff_blocks={len([1 for op in difflib.SequenceMatcher(None, s['a_text'], s['b_text']).get_opcodes() if op[0] != 'equal'])}"
    )
    for tag, i1, i2, j1, j2 in s["blocks"][:3]:
        print(f"  {tag}: aa[{i1}:{i2}] ab[{j1}:{j2}]")
        for line in s["a_text"][i1:min(i2, i1 + 3)]:
            print(f"    - {line}")
        for line in s["b_text"][j1:min(j2, j1 + 3)]:
            print(f"    + {line}")
    print()

print("aa-only functions:")
for f in aa["functions"]:
    if f and f["name"] in {"sub_4D56B3", "sub_4DD64E"}:
        print(f"  {f['name']}: start=0x{f['start']:X} end=0x{f['end']:X} insns={len(f['insns'])}")
