import json
import os

import ida_auto
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_lines
import ida_loader
import ida_nalt
import ida_ua


def clean_line(ea):
    line = ida_lines.generate_disasm_line(ea, 0) or ""
    return ida_lines.tag_remove(line)


def dump_func(ea):
    f = ida_funcs.get_func(ea)
    if not f:
        return None
    rows = []
    cur = f.start_ea
    insn = ida_ua.insn_t()
    while cur < f.end_ea:
        size = ida_ua.decode_insn(insn, cur)
        if size <= 0:
            size = 1
        data = ida_bytes.get_bytes(cur, size) or b""
        rows.append(
            {
                "ea": int(cur),
                "off": int(ida_loader.get_fileregion_offset(cur)),
                "bytes": data.hex(" "),
                "text": clean_line(cur),
            }
        )
        cur += size
    return {
        "start": int(f.start_ea),
        "end": int(f.end_ea),
        "name": ida_funcs.get_func_name(f.start_ea),
        "insns": rows,
    }


def main():
    ida_auto.auto_wait()
    addrs = [int(x, 16) for x in os.environ["CODEX_IDA_ADDRS"].split(",") if x]
    out_path = os.environ["CODEX_IDA_EXPORT"]
    payload = {
        "input": ida_nalt.get_input_file_path(),
        "functions": [dump_func(ea) for ea in addrs],
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
    ida_kernwin.qexit(0)


if __name__ == "__main__":
    main()
