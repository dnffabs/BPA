#!/usr/bin/env python3
"""
extract_imm_func_eid.py — 找出 imm_vex_exp 中值等于函数起始地址的 EID
输出: imm_func_addr_eid.facts，格式: conEid  addr
"""
import argparse


def main():
    p = argparse.ArgumentParser()
    p.add_argument("facts_dir")
    p.add_argument("-o", "--output", required=True)
    args = p.parse_args()

    func_starts = set()
    with open(f"{args.facts_dir}/filtered_func.facts") as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) >= 2:
                try:
                    func_starts.add(int(parts[1]))
                except ValueError:
                    pass

    results = []
    with open(f"{args.facts_dir}/imm_vex_exp.facts") as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) < 3:
                continue
            try:
                val = int(parts[1])
                eid = int(parts[2])
            except ValueError:
                continue
            if val in func_starts:
                results.append(f"{eid}\t{val}")

    with open(args.output, "w") as f:
        f.write("\n".join(results))
        if results:
            f.write("\n")


if __name__ == "__main__":
    main()
