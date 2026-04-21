#!/usr/bin/env python3
"""
extract_heap_calls.py — 从 call_vex_exp.facts 中提取 malloc/calloc/realloc 调用点
输出: heap_alloc_call.facts，格式: func  callSite  allocFunc  size
  - callSite: 十进制指令地址
  - allocFunc: malloc / calloc / realloc
  - size: 静态可知的 size 立即数，否则 -1
"""
import argparse
import re
from elftools.elf.elffile import ELFFile

ALLOC_NAMES = {"malloc", "calloc", "realloc"}


def get_plt_addrs(binary_path):
    """返回 {plt_stub_addr: func_name} for alloc functions"""
    result = {}
    with open(binary_path, 'rb') as f:
        elf = ELFFile(f)
        dynsym = elf.get_section_by_name('.dynsym')
        rela = elf.get_section_by_name('.rela.plt')
        plt_sec = elf.get_section_by_name('.plt.sec') or elf.get_section_by_name('.plt')
        if not (dynsym and rela and plt_sec):
            return result
        plt_base = plt_sec.header.sh_addr
        # .plt.sec: each stub is 0x10 bytes, in rela.plt order
        for i, rel in enumerate(rela.iter_relocations()):
            sym = dynsym.get_symbol(rel['r_info_sym'])
            name = sym.name.split('@')[0]
            if name in ALLOC_NAMES:
                stub_addr = plt_base + i * 0x10
                result[stub_addr] = name
    return result


def load_func_ranges(facts_dir):
    """返回用户函数范围 [(name, start, end)]"""
    builtins = set()
    try:
        with open(f"{facts_dir}/compiler_build_in.facts") as f:
            for line in f:
                builtins.add(line.strip())
    except FileNotFoundError:
        pass
    ranges = []
    with open(f"{facts_dir}/addr_func.facts") as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) < 3:
                continue
            name, start_s, end_s = parts[0], parts[1], parts[2]
            if name in builtins:
                continue
            try:
                start = int(start_s)
                size = int(end_s)
                end = start + size
                if start > 0:
                    ranges.append((name, start, end))
            except ValueError:
                pass
    return ranges


def find_func(irsb_addr, func_ranges):
    for name, start, end in func_ranges:
        if start <= irsb_addr <= end:
            return name
    return None


def load_imm_values(facts_dir):
    """{conEid: value}"""
    result = {}
    with open(f"{facts_dir}/imm_vex_exp.facts") as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) < 3:
                continue
            try:
                result[int(parts[2])] = int(parts[1])
            except ValueError:
                pass
    return result


def get_rdi_eid(facts_dir):
    with open(f"{facts_dir}/get_loc_vex_exp.facts") as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) >= 2 and parts[0] == "rdi":
                return int(parts[1])
    return None


def find_size_arg(facts_dir, rdi_eid, call_irsb, call_instr, imm_values):
    """找 call 之前同一 IRSB 中最近一次 rdi = imm 赋值"""
    best_instr, best_data_eid = -1, None
    with open(f"{facts_dir}/set_loc_vex.facts") as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) < 6:
                continue
            try:
                irsb = int(parts[0])
                instr = int(parts[1])
                data_eid = int(parts[4])
                reg_eid = int(parts[5])
            except ValueError:
                continue
            if irsb == call_irsb and reg_eid == rdi_eid and instr <= call_instr:
                if instr > best_instr:
                    best_instr, best_data_eid = instr, data_eid
    if best_data_eid is not None and best_data_eid in imm_values:
        return imm_values[best_data_eid]
    return -1


def main():
    p = argparse.ArgumentParser()
    p.add_argument("binary")
    p.add_argument("facts_dir")
    p.add_argument("-o", "--output", required=True)
    args = p.parse_args()

    plt_addrs = get_plt_addrs(args.binary)
    if not plt_addrs:
        open(args.output, "w").close()
        return

    func_ranges = load_func_ranges(args.facts_dir)
    imm_values = load_imm_values(args.facts_dir)
    rdi_eid = get_rdi_eid(args.facts_dir)

    results = []
    with open(f"{args.facts_dir}/call_vex_exp.facts") as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) < 4:
                continue
            try:
                irsb_addr = int(parts[1], 16)
                instr_addr = int(parts[2], 16)
            except ValueError:
                continue
            m = re.search(r'\{(\d+)\}', parts[3])
            if not m:
                continue
            target = int(m.group(1))
            if target not in plt_addrs:
                continue
            func = find_func(irsb_addr, func_ranges)
            if func is None:
                continue
            alloc_name = plt_addrs[target]
            size = -1
            if rdi_eid is not None:
                size = find_size_arg(args.facts_dir, rdi_eid, irsb_addr, instr_addr, imm_values)
            results.append(f"{func}\t{instr_addr}\t{alloc_name}\t{size}")

    with open(args.output, "w") as f:
        f.write("\n".join(results))
        if results:
            f.write("\n")


if __name__ == "__main__":
    main()
