#!/usr/bin/env python3
"""
extract_imm_signed.py — 将 imm_vex_exp.facts 中的立即数转为有符号值
只保留绝对值 < 65536 的条目（合理的栈偏移范围）
输出: imm_signed.facts，格式: conEid  signedVal
"""
import argparse
import ctypes


def to_signed(val: int, bits: int) -> int:
    if bits == 32:
        return ctypes.c_int32(val).value
    return ctypes.c_int64(val).value


def main():
    p = argparse.ArgumentParser()
    p.add_argument("input", help="imm_vex_exp.facts path")
    p.add_argument("-o", "--output", required=True)
    args = p.parse_args()

    results = []
    with open(args.input) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 3:
                continue
            sz_str, val_str, con_eid = parts[0], parts[1], parts[2]
            try:
                sz = int(sz_str)
                val = int(val_str)
            except ValueError:
                continue
            signed = to_signed(val, sz)
            if abs(signed) < 65536 and signed != 0:
                results.append(f"{con_eid}\t{signed}")

    with open(args.output, "w") as f:
        f.write("\n".join(results))
        if results:
            f.write("\n")


if __name__ == "__main__":
    main()
