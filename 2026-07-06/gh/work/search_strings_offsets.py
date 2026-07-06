import sys
from pathlib import Path


paths = [Path(p) for p in sys.argv[1:4]]
needles = sys.argv[4:] or ["Licence", "License", "TESTVERSION", "Licence-ID", "Insert"]

for path in paths:
    data = path.read_bytes()
    print(f"FILE {path}")
    for needle in needles:
        hits = []
        for enc, raw in [
            ("ascii", needle.encode("latin1", "ignore")),
            ("utf16", needle.encode("utf-16le")),
        ]:
            start = 0
            while True:
                idx = data.find(raw, start)
                if idx < 0:
                    break
                hits.append((enc, idx))
                start = idx + 1
        if hits:
            print(" ", needle, ":", ", ".join(f"{enc}@0x{idx:X}" for enc, idx in hits[:20]))
        else:
            print(" ", needle, ": not found")
