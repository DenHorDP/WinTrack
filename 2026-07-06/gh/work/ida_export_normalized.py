import hashlib
import json
import os

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_name
import ida_nalt
import ida_segment
import ida_ua


def operand_shape(op):
    if op.type == ida_ua.o_void:
        return ""
    if op.type in (ida_ua.o_near, ida_ua.o_far):
        return "code"
    if op.type == ida_ua.o_imm:
        return "imm"
    if op.type in (ida_ua.o_mem, ida_ua.o_displ):
        return "mem"
    if op.type == ida_ua.o_phrase:
        return "phrase"
    if op.type == ida_ua.o_reg:
        return "reg%d" % op.reg
    return "op%d" % op.type


def normalized_function(f):
    items = []
    ea = f.start_ea
    insn = ida_ua.insn_t()
    while ea < f.end_ea:
        size = ida_ua.decode_insn(insn, ea)
        if size <= 0:
            ea += 1
            continue
        mnem = ida_ua.print_insn_mnem(ea)
        if not mnem:
            ea += size
            continue
        mnem = mnem.lower()
        ops = []
        for i in range(8):
            shape = operand_shape(insn.ops[i])
            if shape:
                ops.append(shape)
        items.append("%s %s" % (mnem, ",".join(ops)))
        ea += size
    text = "\n".join(items).encode("utf-8")
    return len(items), hashlib.sha256(text).hexdigest()[:16]


def main():
    ida_auto.auto_wait()
    out_path = os.environ.get("CODEX_IDA_EXPORT")
    payload = {
        "input": ida_nalt.get_input_file_path(),
        "imagebase": int(ida_nalt.get_imagebase()),
        "functions": [],
    }
    for i in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(i)
        if not f:
            continue
        seg = ida_segment.getseg(f.start_ea)
        seg_name = ida_segment.get_segm_name(seg) if seg else ""
        if seg_name and seg_name.lower() != ".text":
            continue
        count, norm_hash = normalized_function(f)
        payload["functions"].append(
            {
                "ea": int(f.start_ea),
                "end": int(f.end_ea),
                "size": int(f.end_ea - f.start_ea),
                "insns": int(count),
                "name": ida_name.get_name(f.start_ea) or "",
                "norm_hash": norm_hash,
            }
        )
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
    ida_kernwin.qexit(0)


if __name__ == "__main__":
    main()
