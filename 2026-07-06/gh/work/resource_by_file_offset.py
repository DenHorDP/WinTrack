import hashlib
import struct
import sys
from pathlib import Path


def u16(data, o):
    return struct.unpack_from("<H", data, o)[0]


def u32(data, o):
    return struct.unpack_from("<I", data, o)[0]


def analyze(path, offsets):
    data = Path(path).read_bytes()
    pe = u32(data, 0x3C)
    sections = u16(data, pe + 6)
    opt_size = u16(data, pe + 20)
    opt = pe + 24
    res_rva = u32(data, opt + 112)
    secs = []
    so = opt + opt_size
    for _ in range(sections):
        name = data[so : so + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        vsz, va, rsz, raw = struct.unpack_from("<IIII", data, so + 8)
        secs.append((name, va, max(vsz, rsz), raw))
        so += 40

    def rva_to_off(rva):
        for name, va, size, raw in secs:
            if va <= rva < va + size:
                return raw + (rva - va)
        return None

    res_base = rva_to_off(res_rva)

    def res_name(id_value):
        if (id_value & 0x80000000) == 0:
            return f"#{id_value}"
        off = res_base + (id_value & 0x7FFFFFFF)
        n = u16(data, off)
        return data[off + 2 : off + 2 + n * 2].decode("utf-16le", "replace")

    resources = []

    def walk(dir_rel, parts):
        d = res_base + dir_rel
        count = u16(data, d + 12) + u16(data, d + 14)
        for i in range(count):
            e = d + 16 + i * 8
            name = res_name(u32(data, e))
            val = u32(data, e + 4)
            new_parts = parts + [name]
            if val & 0x80000000:
                walk(val & 0x7FFFFFFF, new_parts)
            else:
                de = res_base + val
                rva = u32(data, de)
                size = u32(data, de + 4)
                off = rva_to_off(rva)
                blob = data[off : off + size]
                resources.append(
                    {
                        "path": "/".join(new_parts),
                        "off": off,
                        "end": off + size,
                        "size": size,
                        "sha": hashlib.sha256(blob).hexdigest()[:16],
                    }
                )

    walk(0, [])
    print(f"FILE {path}")
    for off in offsets:
        found = [r for r in resources if r["off"] <= off < r["end"]]
        if found:
            for r in found:
                print(f"  0x{off:X} -> {r['path']} range=0x{r['off']:X}-0x{r['end']-1:X} size={r['size']} sha={r['sha']}")
        else:
            print(f"  0x{off:X} -> no resource")


if __name__ == "__main__":
    analyze(sys.argv[1], [int(x, 16) for x in sys.argv[2:]])
