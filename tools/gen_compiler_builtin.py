#!/usr/bin/env python3
"""
gen_compiler_builtin.py — 从 addr_func.facts 中识别编译器/运行时内建函数
输出: compiler_build_in.facts，格式: func_name（每行一个）
"""
import argparse
import re

# 已知编译器/运行时内建函数名前缀或精确名
_BUILTIN_PATTERNS = [
    re.compile(r'^_start$'),
    re.compile(r'^_init$'),
    re.compile(r'^_fini$'),
    re.compile(r'^_dl_relocate_static_pie$'),
    re.compile(r'^deregister_tm_clones$'),
    re.compile(r'^register_tm_clones$'),
    re.compile(r'^__do_global_dtors_aux$'),
    re.compile(r'^frame_dummy$'),
    re.compile(r'^__libc_csu_'),
    re.compile(r'^__x86\.get_pc_thunk\.'),
    re.compile(r'@'),          # PLT stubs: malloc@GLIBC_2.2.5 等
]


def is_builtin(name: str) -> bool:
    return any(p.search(name) for p in _BUILTIN_PATTERNS)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("input", help="addr_func.facts path")
    p.add_argument("-o", "--output", required=True)
    args = p.parse_args()

    builtins = []
    with open(args.input) as f:
        for line in f:
            parts = line.strip().split('\t')
            if not parts:
                continue
            name = parts[0]
            if is_builtin(name):
                builtins.append(name)

    with open(args.output, "w") as f:
        for name in builtins:
            f.write(name + "\n")


if __name__ == "__main__":
    main()
