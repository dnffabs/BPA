#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse

def convert_two_complement_immediate(infile, outfile=None):
    out_lines = []
    with open(infile, "r") as f:
        for line in f:
            if not line.strip():
                continue

            parts = line.strip().split()
            # 跳过字段不足的行，避免 Soufflé 解析出错
            if len(parts) < 6:
                continue

            # 解析各列：地址、函数、寄存器、操作、立即数、位宽
            addr, func, reg, op, imm_str, width = parts[:6]

            # 仅处理 Add32 的立即数
            if op == "Add32":
                try:
                    imm_value = int(imm_str, 16) if imm_str.lower().startswith("0x") else int(imm_str)
                except ValueError:
                    # 无法解析立即数则跳过此行
                    continue

                # 32 位补码判断：最高位为 1 表示负数
                if imm_value >= 2 ** 31:
                    magnitude = 2 ** 32 - imm_value
                    op = "Sub32"
                    imm_value = magnitude

                imm_str = str(imm_value)

            # 重组输出行：严格只保留 6 列，确保与 local_analysis 声明一致
            new_line = "\t".join([addr, func, reg, op, imm_str, width])
            out_lines.append(new_line)

    if outfile:
        with open(outfile, "w") as out_f:
            if out_lines:
                out_f.write("\n".join(out_lines) + "\n")
            else:
                out_f.write("")
    else:
        if out_lines:
            print("\n".join(out_lines))


def main():
    parser = argparse.ArgumentParser(
        description="Convert two's-complement immediates (Add32) to signed form, keeping address column."
    )
    parser.add_argument("input", help="Input facts file to process")
    parser.add_argument(
        "-o", "--output", dest="output", metavar="FILE",
        help="File to write results to (defaults to stdout)",
    )
    args = parser.parse_args()
    convert_two_complement_immediate(args.input, args.output)


if __name__ == "__main__":
    main()
