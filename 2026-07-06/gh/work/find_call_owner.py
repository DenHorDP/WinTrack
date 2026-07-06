import json
from pathlib import Path


root = Path(r"C:\Users\design\Documents\Codex\2026-07-06\gh\work")
aa = json.loads((root / "trackaa.normalized.json").read_text(encoding="utf-8"))
ab = json.loads((root / "trackab.normalized.json").read_text(encoding="utf-8"))
ba = json.loads((root / "trackba.normalized.json").read_text(encoding="utf-8"))


def owner(doc, ea):
    for f in doc["functions"]:
        if int(f["ea"]) <= ea < int(f["end"]):
            return f
    return None


def key(f):
    return f"{f['insns']}:{f['norm_hash']}"


for label, doc, ea in [("aa", aa, 0x42EAA2), ("ba", ba, 0x4308D2)]:
    f = owner(doc, ea)
    print(f"{label} call 0x{ea:X} owner {f['name']} 0x{int(f['ea']):X}-0x{int(f['end']):X} size={f['size']} insns={f['insns']} key={key(f)}")
    if label == "aa":
        matches = [g for g in ab["functions"] if key(g) == key(f)]
        print("  ab matches:", ", ".join(f"{g['name']}@0x{int(g['ea']):X}" for g in matches))
