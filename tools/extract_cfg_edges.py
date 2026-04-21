#!/usr/bin/env python3
"""
extract_cfg_edges.py — 解析 jmp/call/ret_vex_exp.facts，输出 Soufflé 可用的 CFG 边
输出:
  cfg_edge_raw.facts:   from_irsb  to_irsb  edge_type
  call_site_raw.facts:  caller_irsb  instr_addr  target_addr  (直接调用)
"""
import argparse
import re


def parse_targets(s):
    """'{4198496, 4198528}' → [4198496, 4198528]; 'set()' → []"""
    nums = re.findall(r'\d+', s)
    return [int(n) for n in nums]


def process_file(path, edge_type, edges, call_sites=None):
    try:
        with open(path) as f:
            for line in f:
                parts = line.strip().split('\t')
                if len(parts) < 4:
                    continue
                try:
                    from_irsb = int(parts[1], 16)
                    instr_addr = int(parts[2], 16)
                except ValueError:
                    continue
                targets = parse_targets(parts[3])
                if targets:
                    for t in targets:
                        edges.append((from_irsb, t, edge_type))
                        if call_sites is not None:
                            call_sites.append((from_irsb, instr_addr, t))
                elif call_sites is not None:
                    # set() target = indirect call, record with target=0
                    call_sites.append((from_irsb, instr_addr, 0))
    except FileNotFoundError:
        pass


def main():
    p = argparse.ArgumentParser()
    p.add_argument("facts_dir")
    args = p.parse_args()
    d = args.facts_dir

    edges = []
    call_sites = []

    process_file(f"{d}/jmp_vex_exp.facts",  "jmp",  edges)
    process_file(f"{d}/call_vex_exp.facts", "call", edges, call_sites)
    process_file(f"{d}/ret_vex_exp.facts",  "ret",  edges)

    with open(f"{d}/cfg_edge_raw.facts", "w") as f:
        for from_irsb, to_irsb, etype in edges:
            f.write(f"{from_irsb}\t{to_irsb}\t{etype}\n")

    with open(f"{d}/call_site_raw.facts", "w") as f:
        for caller_irsb, instr_addr, target in call_sites:
            f.write(f"{caller_irsb}\t{instr_addr}\t{target}\n")


if __name__ == "__main__":
    main()
