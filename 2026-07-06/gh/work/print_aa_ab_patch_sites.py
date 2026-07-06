import json
from pathlib import Path


root = Path(r"C:\Users\design\Documents\Codex\2026-07-06\gh\work")
aa = json.loads((root / "trackaa.selected.json").read_text(encoding="utf-8"))
ab = json.loads((root / "trackab.selected.json").read_text(encoding="utf-8"))


def by_name(doc):
    return {f["name"]: f for f in doc["functions"] if f}


for label, funcs, sites in [
    (
        "aa",
        by_name(aa),
        {
            "sub_4715B0": range(7, 16),
            "sub_4720A0": range(112, 128),
            "sub_476880": range(7, 16),
        },
    ),
    (
        "ab",
        by_name(ab),
        {
            "sub_471560": range(7, 16),
            "sub_472050": range(112, 124),
            "sub_476840": range(7, 16),
        },
    ),
]:
    print(f"### {label}")
    for name, indexes in sites.items():
        f = funcs[name]
        print(f"=== {name} start=0x{f['start']:X} ===")
        for i in indexes:
            if i >= len(f["insns"]):
                continue
            row = f["insns"][i]
            print(f"{i:03d} ea=0x{row['ea']:X} off=0x{row['off']:X} bytes={row['bytes']:<24} {row['text']}")
        print()
