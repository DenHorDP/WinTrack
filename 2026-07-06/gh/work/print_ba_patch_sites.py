import json
from pathlib import Path


root = Path(r"C:\Users\design\Documents\Codex\2026-07-06\gh\work")
ba = json.loads((root / "trackba.selected.json").read_text(encoding="utf-8"))
funcs = {f["name"]: f for f in ba["functions"] if f}

sites = {
    "sub_47B6C0": range(7, 16),
    "sub_47C280": range(112, 128),
    "sub_481320": range(7, 16),
}

for name, indexes in sites.items():
    f = funcs[name]
    print(f"=== {name} start=0x{f['start']:X} ===")
    for i in indexes:
        if i >= len(f["insns"]):
            continue
        row = f["insns"][i]
        print(f"{i:03d} ea=0x{row['ea']:X} off=0x{row['off']:X} bytes={row['bytes']:<24} {row['text']}")
    print()
