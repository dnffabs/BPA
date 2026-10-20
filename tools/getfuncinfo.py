#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from elftools.elf.elffile import ELFFile

def extract_and_convert_functions(binary_path, output_file="addr_func.facts"):
    """
    从 ELF 文件中提取函数信息，并将地址从十六进制转换为十进制，写入输出文件。

    Args:
        binary_path (str): ELF 二进制文件路径
        output_file (str): 输出文件路径，默认为 "addr_func.facts"
    """
    # 打开 ELF 文件
    with open(binary_path, 'rb') as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name('.symtab')

        if not symtab:
            from pathlib import Path
            Path(output_file).unlink(missing_ok=True)
            raise SystemExit("错误：未找到 .symtab 节；stripped 函数恢复尚未实现")

        # 收集函数信息
        functions = [
            (symbol.name, symbol['st_value'], symbol['st_size'])
            for symbol in symtab.iter_symbols()
            if symbol['st_info']['type'] == 'STT_FUNC'
        ]

        # 直接写入结果文件
        with open(output_file, 'w') as out:
            for name, addr, size in functions:
                # addr 已为十进制，无需转换，直接使用
                out.write(f"{name}\t{addr}\t{size}\n")
                print(f"{name:30} 0x{addr:016x} {size:8}")

def main():
    # 设置命令行参数解析
    parser = argparse.ArgumentParser(
        description="从 ELF 文件中提取函数信息并保存",
        usage="%(prog)s <binary_path> [-o output_file]"
    )
    parser.add_argument("binary_path", help="ELF 二进制文件路径")
    parser.add_argument("-o", "--output", default="addr_func.facts",
                       help="输出文件路径（默认：addr_func.facts）")

    args = parser.parse_args()

    # 执行函数提取和转换
    extract_and_convert_functions(args.binary_path, args.output)

if __name__ == "__main__":
    main()
