import struct
import sys
from pathlib import Path


path = Path(sys.argv[1])
needle = sys.argv[2].lower() if len(sys.argv) > 2 else ""
data = path.read_bytes()


def u16(o):
    return struct.unpack_from("<H", data, o)[0]


def u32(o):
    return struct.unpack_from("<I", data, o)[0]


pe = u32(0x3C)
sections = u16(pe + 6)
opt_size = u16(pe + 20)
opt = pe + 24
res_rva = u32(opt + 112)
secs = []
so = opt + opt_size
for _ in range(sections):
    name = data[so : so + 8].split(b"\0", 1)[0].decode("ascii", "replace")
    vsz, va, rsz, raw = struct.unpack_from("<IIII", data, so + 8)
    secs.append((name, va, max(vsz, rsz), raw))
    so += 40


def rva_to_off(rva):
    for _name, va, size, raw in secs:
        if va <= rva < va + size:
            return raw + (rva - va)
    raise ValueError(hex(rva))


res_base = rva_to_off(res_rva)


def res_name_at(id_value):
    if (id_value & 0x80000000) == 0:
        return f"#{id_value}"
    off = res_base + (id_value & 0x7FFFFFFF)
    n = u16(off)
    raw = data[off + 2 : off + 2 + n * 2]
    return raw.decode("utf-16le", "replace")


def entries(dir_rel):
    d = res_base + dir_rel
    count = u16(d + 12) + u16(d + 14)
    for i in range(count):
        e = d + 16 + i * 8
        name = res_name_at(u32(e))
        val = u32(e + 4)
        yield name, val


def read_word(blob, pos):
    return struct.unpack_from("<H", blob, pos)[0], pos + 2


def read_dword(blob, pos):
    return struct.unpack_from("<I", blob, pos)[0], pos + 4


def read_name(blob, pos):
    val, pos = read_word(blob, pos)
    if val == 0:
        return "", pos
    if val == 0xFFFF:
        ident, pos = read_word(blob, pos)
        return f"#{ident}", pos
    chars = [val]
    while True:
        val, pos = read_word(blob, pos)
        if val == 0:
            break
        chars.append(val)
    return struct.pack("<" + "H" * len(chars), *chars).decode("utf-16le", "replace"), pos


def read_string(blob, pos):
    chars = []
    while True:
        val, pos = read_word(blob, pos)
        if val == 0:
            break
        chars.append(val)
    if not chars:
        return "", pos
    return struct.pack("<" + "H" * len(chars), *chars).decode("utf-16le", "replace"), pos


def align4(pos):
    return (pos + 3) & ~3


def dialog_summary(blob):
    pos = 0
    dlgex = len(blob) >= 4 and struct.unpack_from("<HH", blob, 0) == (1, 0xFFFF)
    if dlgex:
        pos = 4
        _help, pos = read_dword(blob, pos)
        _ex, pos = read_dword(blob, pos)
        style, pos = read_dword(blob, pos)
        cdit, pos = read_word(blob, pos)
        pos += 8
    else:
        style, pos = read_dword(blob, pos)
        _ex, pos = read_dword(blob, pos)
        cdit, pos = read_word(blob, pos)
        pos += 8
    _menu, pos = read_name(blob, pos)
    _klass, pos = read_name(blob, pos)
    caption, pos = read_string(blob, pos)
    texts = [caption]
    if style & 0x40:
        _point, pos = read_word(blob, pos)
        if dlgex:
            pos += 6
        _font, pos = read_string(blob, pos)
    pos = align4(pos)
    for _ in range(cdit):
        if dlgex:
            pos += 12
            pos += 12
        else:
            pos += 8
            pos += 10
        _cls, pos = read_name(blob, pos)
        title, pos = read_name(blob, pos)
        if title:
            texts.append(title)
        extra, pos = read_word(blob, pos)
        pos = align4(pos + extra)
        if pos >= len(blob):
            break
    return caption, texts


for t_name, t_val in entries(0):
    if t_name != "#5":
        continue
    type_dir = t_val & 0x7FFFFFFF
    for dlg_id, dlg_val in entries(type_dir):
        name_dir = dlg_val & 0x7FFFFFFF
        for lang, data_val in entries(name_dir):
            de = res_base + data_val
            rva = u32(de)
            size = u32(de + 4)
            off = rva_to_off(rva)
            blob = data[off : off + size]
            try:
                caption, texts = dialog_summary(blob)
            except Exception:
                continue
            joined = " | ".join(texts)
            if not needle or needle in joined.lower():
                safe = joined.encode("ascii", "backslashreplace").decode("ascii")
                print(f"{dlg_id}/{lang}: {safe}")
