#!/usr/bin/env python3
import argparse

def convert_offset(val: str) -> str:
    """把偏移量字符串转为补码形式（只处理十进制）"""
    try:
        n = int(val)
    except ValueError:
        return val  # 不是数字就原样返回

    if n >= 2**31:       # 如果是大于等于 0x80000000 的无符号值
        return str(n - 2**32)
    return str(n)

def process_line(line: str) -> str:
    parts = line.strip().split()
    if len(parts) >= 4:
        parts[2] = convert_offset(parts[2])
        return "\t".join(parts)
    return line.rstrip()

def main():
    parser = argparse.ArgumentParser(
        description="把 EBP 偏移量中大于等于 2^31 的值转成 32 位补码"
    )
    parser.add_argument("input_file", help="输入文件")
    parser.add_argument("-o", "--output", dest="output_file", required=True,
                        help="输出文件")
    args = parser.parse_args()

    with open(args.input_file, "r") as fin, open(args.output_file, "w") as fout:
        for line in fin:
            fout.write(process_line(line) + "\n")

if __name__ == "__main__":
    main()
