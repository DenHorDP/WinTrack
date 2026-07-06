import json
from pathlib import Path


root = Path(r"C:\Users\design\Documents\Codex\2026-07-06\gh\work")
aa = json.loads((root / "trackaa.normalized.json").read_text(encoding="utf-8"))
ab = json.loads((root / "trackab.normalized.json").read_text(encoding="utf-8"))
ba = json.loads((root / "trackba.normalized.json").read_text(encoding="utf-8"))

aa_changed = {
    0x41C870,
    0x43C380,
    0x43D390,
    0x4715B0,
    0x4720A0,
    0x476880,
    0x497330,
    0x4ADC00,
    0x4B0820,
    0x4B2B00,
    0x4D56B3,
    0x4DD64E,
}
ab_changed = {
    0x41C8C0,
    0x43C2F0,
    0x43D300,
    0x471560,
    0x472050,
    0x476840,
    0x4972C0,
    0x4ADBB0,
    0x4B07D0,
    0x4B2AA0,
}


def by_ea(doc):
    return {int(f["ea"]): f for f in doc["functions"]}


def key(f):
    return f"{f['insns']}:{f['norm_hash']}"


aa_by_ea = by_ea(aa)
ab_by_ea = by_ea(ab)
ba_funcs = ba["functions"]
ba_by_key = {}
for f in ba_funcs:
    ba_by_key.setdefault(key(f), []).append(f)

print(f"trackba funcs={len(ba_funcs)}")
print("--- direct matches for trackab changed-function shapes ---")
for ea in sorted(ab_changed):
    f = ab_by_ea[ea]
    matches = ba_by_key.get(key(f), [])
    print(
        f"ab {f['name']} 0x{ea:X} size={f['size']} insns={f['insns']} "
        f"matches_in_ba={len(matches)} "
        + ", ".join(f"{m['name']}@0x{int(m['ea']):X}" for m in matches[:5])
    )

print("--- direct matches for trackaa old-function shapes ---")
for ea in sorted(aa_changed):
    f = aa_by_ea[ea]
    matches = ba_by_key.get(key(f), [])
    print(
        f"aa {f['name']} 0x{ea:X} size={f['size']} insns={f['insns']} "
        f"matches_in_ba={len(matches)} "
        + ", ".join(f"{m['name']}@0x{int(m['ea']):X}" for m in matches[:5])
    )

print("--- nearest size/insn candidates for each ab changed function ---")
for ea in sorted(ab_changed):
    f = ab_by_ea[ea]
    cands = sorted(
        ba_funcs,
        key=lambda g: (
            abs(int(g["insns"]) - int(f["insns"])),
            abs(int(g["size"]) - int(f["size"])),
        ),
    )[:6]
    print(f"ab {f['name']} size={f['size']} insns={f['insns']}")
    for c in cands:
        print(f"  ba {c['name']}@0x{int(c['ea']):X} size={c['size']} insns={c['insns']} hash={c['norm_hash']}")
