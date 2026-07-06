import hashlib
import json
import os

import ida_auto
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import ida_nalt
import ida_segment


def get_input_path():
    try:
        return ida_nalt.get_input_file_path()
    except Exception:
        return ida_nalt.get_root_filename()


def iter_functions():
    for i in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(i)
        if not f:
            continue
        seg = ida_segment.getseg(f.start_ea)
        seg_name = ida_segment.get_segm_name(seg) if seg else ""
        if seg_name and seg_name.lower() != ".text":
            continue
        size = max(0, f.end_ea - f.start_ea)
        data = ida_bytes.get_bytes(f.start_ea, size) or b""
        yield {
            "ea": int(f.start_ea),
            "end": int(f.end_ea),
            "size": int(size),
            "name": ida_name.get_name(f.start_ea) or "",
            "sha256_16": hashlib.sha256(data).hexdigest()[:16],
        }


def main():
    ida_auto.auto_wait()
    input_path = get_input_path()
    out_path = os.environ.get("CODEX_IDA_EXPORT")
    if not out_path:
        base = os.path.splitext(os.path.basename(input_path))[0]
        out_path = os.path.join(os.getcwd(), base + ".functions.json")
    payload = {
        "input": input_path,
        "imagebase": int(ida_nalt.get_imagebase()),
        "functions": list(iter_functions()),
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
    ida_kernwin.qexit(0)


if __name__ == "__main__":
    main()
