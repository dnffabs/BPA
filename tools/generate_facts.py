#!/usr/bin/env python3
import argparse
import os
import sys
from contextlib import redirect_stdout, redirect_stderr


def generate(binary_path: str, output_dir: str) -> None:
    tools_dir = os.path.dirname(os.path.abspath(__file__))
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)

    # 延迟导入，避免 -h 时因依赖缺失报错
    from vex2Datalog.extractUtil import extract_cfg, extract_nodes, extract_block
    from vex2Datalog.parser import Parser

    # 保持安静：屏蔽库内部的 print 输出
    devnull_path = os.devnull
    with open(devnull_path, "w") as devnull:
        with redirect_stdout(devnull), redirect_stderr(devnull):
            cfg, arch = extract_cfg(binary_path)
            for node in extract_nodes(cfg):
                block = extract_block(node)
                if block is None:
                    continue
                Parser.initialize_parser(block.vex, arch)
                Parser.parse_block_vex()

    os.makedirs(output_dir, exist_ok=True)
    # 写文件本身不额外打印
    Parser.get_facts().write_to_file(output_dir)


def main():
    p = argparse.ArgumentParser(
        description="Generate Datalog facts from a binary quietly (no stdout)."
    )
    p.add_argument("binary_path", help="Path to input ELF binary")
    p.add_argument("-o", "--output", default="output", help="Directory to store facts")
    args = p.parse_args()
    generate(args.binary_path, args.output)


if __name__ == "__main__":
    main()
