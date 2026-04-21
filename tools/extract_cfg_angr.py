#!/usr/bin/env python3
"""
extract_cfg_angr.py — 用 angr CFGFast 提取基本块 CFG 边
输出: cfg_edge_raw.facts  from_irsb  to_irsb  edge_type
      call_site_raw.facts  caller_irsb  instr_addr  target_addr
"""
import argparse
import os
import sys
from contextlib import redirect_stdout, redirect_stderr


def main():
    p = argparse.ArgumentParser()
    p.add_argument("binary")
    p.add_argument("facts_dir")
    args = p.parse_args()

    tools_dir = os.path.dirname(os.path.abspath(__file__))
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)

    with open(os.devnull, "w") as devnull:
        with redirect_stdout(devnull), redirect_stderr(devnull):
            from vex2Datalog.extractUtil import extract_cfg
            cfg, _ = extract_cfg(args.binary)

    edges = []
    call_sites = []

    for src, dst, data in cfg.graph.edges(data=True):
        src_addr = src.addr
        dst_addr = dst.addr
        jk = getattr(src.block, 'jumpkind', None) if src.block else None
        if jk is None:
            # fallback: use edge data or default
            jk = data.get('jumpkind', 'Ijk_Boring')

        if jk == 'Ijk_Call':
            etype = 'call'
            # call_site instr = last instruction of src block
            last_instr = src_addr
            if src.block and src.block.instruction_addrs:
                last_instr = src.block.instruction_addrs[-1]
            call_sites.append((src_addr, last_instr, dst_addr))
        elif jk == 'Ijk_Ret':
            etype = 'ret'
        elif jk == 'Ijk_Boring':
            etype = 'jmp'
        else:
            etype = jk.replace('Ijk_', '').lower()

        edges.append((src_addr, dst_addr, etype))

    d = args.facts_dir
    with open(f"{d}/cfg_edge_raw.facts", "w") as f:
        for fr, to, et in edges:
            f.write(f"{fr}\t{to}\t{et}\n")

    with open(f"{d}/call_site_raw.facts", "w") as f:
        for caller_irsb, instr, target in call_sites:
            f.write(f"{caller_irsb}\t{instr}\t{target}\n")


if __name__ == "__main__":
    main()
