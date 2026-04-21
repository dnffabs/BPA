#!/usr/bin/env python3
"""
extract_imm_global_eid.py — 找出 imm_vex_exp 中值等于全局地址候选的 EID
输出: imm_global_eid.facts，格式: conEid  addr
"""
import argparse


def main():
    p = argparse.ArgumentParser()
    p.add_argument("facts_dir")
    p.add_argument("-o", "--output", required=True)
    args = p.parse_args()

    # 读取全局地址候选集合
    candidates = set()
    with open(f"{args.facts_dir}/global_addr_candidates.facts") as f:
        for line in f:
            line = line.strip()
            if line:
                candidates.add(int(line))

    results = []
    with open(f"{args.facts_dir}/imm_vex_exp.facts") as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) < 3:
                continue
            val_str, con_eid = parts[1], parts[2]
            try:
                val = int(val_str)
            except ValueError:
                continue
            if val in candidates:
                results.append(f"{con_eid}\t{val}")

    with open(args.output, "w") as f:
        f.write("\n".join(results))
        if results:
            f.write("\n")


if __name__ == "__main__":
    main()
