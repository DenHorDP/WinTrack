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


def line(ea):
    return ida_lines.tag_remove(ida_lines.generate_disasm_line(ea, 0) or "")


def main():
    ida_auto.auto_wait()
    addrs = [int(x, 16) for x in os.environ["CODEX_IDA_ADDRS"].split(",") if x]
    out = []
    for center in addrs:
        f = ida_funcs.get_func(center)
        rows = []
        start = max(center - 64, 0)
        ea = start
        insn = ida_ua.insn_t()
        while ea < center + 64:
            size = ida_ua.decode_insn(insn, ea)
            if size <= 0:
                size = 1
            data = ida_bytes.get_bytes(ea, size) or b""
            rows.append(
                {
                    "ea": int(ea),
                    "off": int(ida_loader.get_fileregion_offset(ea)),
                    "bytes": data.hex(" "),
                    "text": line(ea),
                }
            )
            ea += size
        out.append(
            {
                "center": center,
                "func": None if not f else {"start": int(f.start_ea), "end": int(f.end_ea), "name": ida_funcs.get_func_name(f.start_ea)},
                "rows": rows,
            }
        )
    with open(os.environ["CODEX_IDA_EXPORT"], "w", encoding="utf-8") as f:
        json.dump({"input": ida_nalt.get_input_file_path(), "items": out}, f, indent=2)
    ida_kernwin.qexit(0)


if __name__ == "__main__":
    main()
