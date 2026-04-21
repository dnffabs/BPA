#!/usr/bin/env python3
"""
extract_global_addrs.py — 从 imm_vex_exp.facts 中提取落在全局段内的地址候选
输出: global_addr_candidates.facts，每行一个十进制地址
"""
import argparse
import sys


def load_sections(facts_dir):
    """加载 .data/.bss/.rodata 段范围"""
    regions = []
    for name in ("data", "bss", "rodata"):
        path = f"{facts_dir}/{name}.facts"
        try:
            with open(path) as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        regions.append((int(parts[0]), int(parts[1])))
        except FileNotFoundError:
            pass
    return regions


def in_any_region(val, regions):
    return any(start <= val < end for start, end in regions)


def main():
    p = argparse.ArgumentParser(description="Extract global address candidates from imm_vex_exp.facts")
    p.add_argument("facts_dir", help="Directory containing .facts files")
    p.add_argument("-o", "--output", required=True, help="Output file path")
    args = p.parse_args()

    regions = load_sections(args.facts_dir)
    if not regions:
        print("[WARN] No global sections found", file=sys.stderr)
        open(args.output, "w").close()
        return

    candidates = set()
    # 加入段起始地址
    for start, _ in regions:
        candidates.add(start)

    # 从 imm_vex_exp 提取候选
    imm_path = f"{args.facts_dir}/imm_vex_exp.facts"
    try:
        with open(imm_path) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 3:
                    continue
                val_str = parts[1]
                # 只处理合理长度的十进制数（避免 64 位大数）
                if not val_str.isdigit() or len(val_str) > 10:
                    continue
                val = int(val_str)
                if in_any_region(val, regions):
                    candidates.add(val)
    except FileNotFoundError:
        print(f"[WARN] {imm_path} not found", file=sys.stderr)

    with open(args.output, "w") as f:
        for addr in sorted(candidates):
            f.write(f"{addr}\n")


if __name__ == "__main__":
    main()
