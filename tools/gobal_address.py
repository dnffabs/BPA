#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import argparse
import sys

def extract_unique_hex(facts_file):
    """
    从输入文件中提取十六进制内容，去除重复并返回一个排序的整数列表。
    """
    hex_set = set()
    with open(facts_file, "r") as f:
        for line in f:
            if not line.strip():
                continue
            parts = line.strip().split()
            if len(parts) < 5:
                continue
            hex_values = re.findall(r'\b0x[0-9a-fA-F]+\b', " ".join(parts))
            hex_set.update(hex_values)
    # 转换为十进制整数，并排序
    dec_list = sorted(int(hx, 16) for hx in hex_set)
    return dec_list


def main():
    parser = argparse.ArgumentParser(
        description="Extract and dedupe hex immediates from a facts file, output in decimal."
    )
    parser.add_argument(
        "input", help="Input facts file to process"
    )
    parser.add_argument(
        "-o", "--output", help="File to write results to (defaults to stdout)",
        dest="output", metavar="FILE"
    )
    args = parser.parse_args()

    dec_list = extract_unique_hex(args.input)
    if args.output:
        try:
            with open(args.output, 'w') as out_f:
                for val in dec_list:
                    out_f.write(str(val) + "\n")
        except IOError as e:
            sys.stderr.write(f"Error writing to {args.output}: {e}\n")
            sys.exit(1)
    else:
        for val in dec_list:
            print(val)

if __name__ == "__main__":
    main()
