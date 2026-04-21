import argparse
import os
import sys


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # better/tools
# 将包的父目录（tools）加入 sys.path，便于 import vex2Datalog.*
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from vex2Datalog.extractUtil import extract_cfg, print_cfg, extract_nodes, extract_block
from vex2Datalog.parser import Parser


def Datalog_gen(binary_path, output_dir):
    test_cfg, arch = extract_cfg(binary_path)
    print_cfg(test_cfg)
    nodes = extract_nodes(test_cfg)
    for node in nodes:
        block = extract_block(node)
        if block is not None:
            print("\n")
            print("========this is a block=========================>")
            print(block.vex)
            print(block.disassembly)
            print("========block over==============================>")
            print("\n")
            # 进行数据流分析
            # build_du_ud_chains(block.vex.statements)
            Parser.initialize_parser(block.vex, arch)
            Parser.parse_block_vex()

    # Parser.get_facts().PrintFacts()

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    Parser.get_facts().write_to_file(output_dir)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract CFG and generate Datalog facts from a binary.')
    parser.add_argument('binary_path', type=str, help='Path to the binary file')
    parser.add_argument('-o', '--output', type=str, default='output', help='Directory to store output facts')
    args = parser.parse_args()
    Datalog_gen(args.binary_path, args.output)
