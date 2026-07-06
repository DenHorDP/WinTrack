import sys
import struct
from pathlib import Path


path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(r"E:\Soft\trackaa.exe")
dialog_id = int(sys.argv[2]) if len(sys.argv) > 2 else 203
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


def entry_by_id(dir_rel, wanted):
    d = res_base + dir_rel
    named = u16(d + 12)
    ids = u16(d + 14)
    for i in range(named + ids):
        e = d + 16 + i * 8
        name_id = u32(e)
        val = u32(e + 4)
        if (name_id & 0x80000000) == 0 and name_id == wanted:
            return val
    raise KeyError(wanted)


type_dir = entry_by_id(0, 5) & 0x7FFFFFFF
name_dir = entry_by_id(type_dir, dialog_id) & 0x7FFFFFFF

lang_entries = []
d = res_base + name_dir
count = u16(d + 12) + u16(d + 14)
for i in range(count):
    e = d + 16 + i * 8
    lang_entries.append((u32(e), u32(e + 4)))

print(f"{path} RT_DIALOG #{dialog_id} languages:", ", ".join(f"#{x[0]}" for x in lang_entries))

lang, data_entry_rel = lang_entries[0]
de = res_base + data_entry_rel
rva = u32(de)
size = u32(de + 4)
off = rva_to_off(rva)
blob = data[off : off + size]
print(f"size={size} file_off=0x{off:X} rva=0x{rva:X}")


def align4(pos):
    return (pos + 3) & ~3


def read_word_blob(pos):
    return struct.unpack_from("<H", blob, pos)[0], pos + 2


def read_dword_blob(pos):
    return struct.unpack_from("<I", blob, pos)[0], pos + 4


def read_res_name(pos):
    val, pos = read_word_blob(pos)
    if val == 0:
        return None, pos
    if val == 0xFFFF:
        ident, pos = read_word_blob(pos)
        return f"#{ident}", pos
    chars = [val]
    while True:
        val, pos = read_word_blob(pos)
        if val == 0:
            break
        chars.append(val)
    return bytes(struct.pack("<" + "H" * len(chars), *chars)).decode("utf-16le", "replace"), pos


def read_u16_string(pos):
    chars = []
    while True:
        val, pos = read_word_blob(pos)
        if val == 0:
            break
        chars.append(val)
    if not chars:
        return "", pos
    return bytes(struct.pack("<" + "H" * len(chars), *chars)).decode("utf-16le", "replace"), pos


pos = 0
dlgex = len(blob) >= 4 and struct.unpack_from("<HH", blob, 0) == (1, 0xFFFF)
if dlgex:
    pos = 4
    help_id, pos = read_dword_blob(pos)
    ex_style, pos = read_dword_blob(pos)
    style, pos = read_dword_blob(pos)
    cdit, pos = read_word_blob(pos)
    x, y, cx, cy = struct.unpack_from("<hhhh", blob, pos)
    pos += 8
else:
    style, pos = read_dword_blob(pos)
    ex_style, pos = read_dword_blob(pos)
    cdit, pos = read_word_blob(pos)
    x, y, cx, cy = struct.unpack_from("<hhhh", blob, pos)
    pos += 8

menu, pos = read_res_name(pos)
klass, pos = read_res_name(pos)
caption, pos = read_u16_string(pos)
print(f"dialogex={dlgex} style=0x{style:X} exstyle=0x{ex_style:X} controls={cdit} rect=({x},{y},{cx},{cy})")
print(f"menu={menu!r} class={klass!r} caption={caption!r}")

if style & 0x40:
    point, pos = read_word_blob(pos)
    weight, pos = read_word_blob(pos) if dlgex else (None, pos)
    italic, pos = read_word_blob(pos) if dlgex else (None, pos)
    charset, pos = read_word_blob(pos) if dlgex else (None, pos)
    face, pos = read_u16_string(pos)
    print(f"font={face!r} point={point}")

pos = align4(pos)
for idx in range(cdit):
    start = pos
    if dlgex:
        help_id, pos = read_dword_blob(pos)
        ex_style, pos = read_dword_blob(pos)
        style, pos = read_dword_blob(pos)
        x, y, cx, cy, ctrl_id = struct.unpack_from("<hhhhI", blob, pos)
        pos += 12
    else:
        style, pos = read_dword_blob(pos)
        ex_style, pos = read_dword_blob(pos)
        x, y, cx, cy, ctrl_id = struct.unpack_from("<hhhhh", blob, pos)
        pos += 10
    cls, pos = read_res_name(pos)
    title, pos = read_res_name(pos)
    extra_len, pos = read_word_blob(pos)
    pos += extra_len
    pos = align4(pos)
    print(f"control[{idx}] id={ctrl_id} class={cls!r} title={title!r} rect=({x},{y},{cx},{cy}) style=0x{style:X}")

print("utf16 strings:")
strings = []
cur = []
for i in range(0, len(blob) - 1, 2):
    val = struct.unpack_from("<H", blob, i)[0]
    if 32 <= val <= 0xFFFD:
        cur.append(val)
    else:
        if len(cur) >= 2:
            strings.append(bytes(struct.pack("<" + "H" * len(cur), *cur)).decode("utf-16le", "replace"))
        cur = []
if len(cur) >= 2:
    strings.append(bytes(struct.pack("<" + "H" * len(cur), *cur)).decode("utf-16le", "replace"))
for s in strings:
    print(("  " + s).encode("ascii", "backslashreplace").decode("ascii"))
