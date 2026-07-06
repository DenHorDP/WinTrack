import json
import os

import ida_auto
import ida_kernwin
import ida_nalt
import ida_xref


def main():
    ida_auto.auto_wait()
    addrs = [int(x, 16) for x in os.environ["CODEX_IDA_ADDRS"].split(",") if x]
    out = []
    for ea in addrs:
        refs = []
        xr = ida_xref.xrefblk_t()
        ok = xr.first_to(ea, ida_xref.XREF_ALL)
        while ok:
            refs.append({"frm": int(xr.frm), "to": int(xr.to), "type": int(xr.type), "iscode": bool(xr.iscode)})
            ok = xr.next_to()
        out.append({"ea": ea, "refs": refs})
    with open(os.environ["CODEX_IDA_EXPORT"], "w", encoding="utf-8") as f:
        json.dump({"input": ida_nalt.get_input_file_path(), "xrefs": out}, f, indent=2)
    ida_kernwin.qexit(0)


if __name__ == "__main__":
    main()
