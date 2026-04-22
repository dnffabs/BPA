#!/usr/bin/env python3
"""
One-shot evaluation: extract DWARF GT then compare with predicted facts.

Usage:
    python evaluate.py <binary> <stack_boundary.facts> <global_boundary.facts>
"""
import sys
import os
from datetime import datetime

# ── import GT extractor ──────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))
from extract_dwarf_gt import process as extract_gt


# Variables larger than this are structs passed by pointer — prediction cannot
# infer their total size from single-access VEX IR, so exclude from comparison.
STACK_SIZE_LIMIT = 4096


def load_stack(path, size_limit=STACK_SIZE_LIMIT):
    """Return set of (func, offset, size) from a stack_boundary.facts-style file."""
    s = set()
    with open(path) as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) == 3:
                sz = int(parts[2])
                if sz <= size_limit:
                    s.add((parts[0], int(parts[1]), sz))
    return s


def load_global(path):
    """Return set of (addr, size) from a global_boundary.facts-style file."""
    s = set()
    with open(path) as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) == 2:
                s.add((int(parts[0]), int(parts[1])))
    return s


def metrics(pred: set, gt: set):
    tp = len(pred & gt)
    fp = len(pred - gt)
    fn = len(gt - pred)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return tp, fp, fn, precision, recall, f1


def metrics_stack_offset(pred_set, gt_set):
    """
    Stack variable matching by (func, offset), tolerating size differences.
    Prediction can only observe access size, which may be smaller than the
    full variable size reported by DWARF.  A predicted (func, offset, ps)
    is TP if there exists a GT (func, offset, gs) with ps <= gs.
    """
    # Build lookup: (func, offset) -> max size
    gt_by_key = {}
    for func, off, sz in gt_set:
        key = (func, off)
        gt_by_key[key] = max(gt_by_key.get(key, 0), sz)

    pred_by_key = {}
    for func, off, sz in pred_set:
        key = (func, off)
        pred_by_key[key] = max(pred_by_key.get(key, 0), sz)

    tp_keys = set()
    for key, psz in pred_by_key.items():
        if key in gt_by_key and psz <= gt_by_key[key]:
            tp_keys.add(key)

    tp = len(tp_keys)
    fp = len(pred_by_key) - tp
    fn = len(gt_by_key) - len(tp_keys & set(gt_by_key.keys()))
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return tp, fp, fn, precision, recall, f1, gt_by_key, pred_by_key, tp_keys


def metrics_global_overlap(pred_list, gt_list):
    """
    Global variable matching by interval overlap instead of exact match.
    A predicted interval [pa, pa+ps) is TP if it overlaps with some GT interval [ga, ga+gs).
    Each GT interval can only be matched once (greedy by overlap size).
    """
    # build intervals
    pred_ivs = [(a, a + s) for a, s in pred_list]
    gt_ivs   = [(a, a + s) for a, s in gt_list]

    matched_gt = set()
    tp_pred = set()
    for i, (pa, pe) in enumerate(pred_ivs):
        for j, (ga, ge) in enumerate(gt_ivs):
            if j in matched_gt:
                continue
            if pa < ge and pe > ga:   # overlap
                matched_gt.add(j)
                tp_pred.add(i)
                break

    tp = len(tp_pred)
    fp = len(pred_ivs) - tp
    fn = len(gt_ivs) - len(matched_gt)
    precision = tp / len(pred_ivs) if pred_ivs else 0.0
    recall    = tp / len(gt_ivs)   if gt_ivs   else 0.0
    f1 = 2*precision*recall/(precision+recall) if (precision+recall) else 0.0
    return tp, fp, fn, precision, recall, f1


def report(name, pred, gt, out=None, use_overlap=False, use_stack_offset=False):
    def w(line=''):
        print(line)
        if out:
            out.write(line + '\n')
    if use_overlap:
        pred_list = sorted(pred)
        gt_list   = sorted(gt)
        tp, fp, fn, p, r, f1 = metrics_global_overlap(pred_list, gt_list)
        w(f"\n=== {name} (interval-overlap matching) ===")
    elif use_stack_offset:
        tp, fp, fn, p, r, f1, gt_by_key, pred_by_key, tp_keys = metrics_stack_offset(pred, gt)
        w(f"\n=== {name} (offset matching, size tolerant) ===")
        w(f"  GT entries   : {len(gt_by_key)}")
        w(f"  Pred entries : {len(pred_by_key)}")
        w(f"  TP={tp}  FP={fp}  FN={fn}")
        w(f"  Precision : {p:.4f}")
        w(f"  Recall    : {r:.4f}")
        w(f"  F1        : {f1:.4f}")
        fn_keys = set(gt_by_key.keys()) - tp_keys
        fp_keys = set(pred_by_key.keys()) - tp_keys
        if fn_keys:
            w("  Missing (in GT but not predicted):")
            for key in sorted(fn_keys):
                w(f"    {key}  size={gt_by_key[key]}")
        if fp_keys:
            w("  Extra (predicted but not in GT):")
            for key in sorted(fp_keys):
                w(f"    {key}  size={pred_by_key[key]}")
        return
    else:
        tp, fp, fn, p, r, f1 = metrics(pred, gt)
        w(f"\n=== {name} ===")
    w(f"  GT entries   : {len(gt)}")
    w(f"  Pred entries : {len(pred)}")
    w(f"  TP={tp}  FP={fp}  FN={fn}")
    w(f"  Precision : {p:.4f}")
    w(f"  Recall    : {r:.4f}")
    w(f"  F1        : {f1:.4f}")
    if not use_overlap:
        if fn:
            w("  Missing (in GT but not predicted):")
            for item in sorted(gt - pred):
                w(f"    {item}")
        if fp:
            w("  Extra (predicted but not in GT):")
            for item in sorted(pred - gt):
                w(f"    {item}")


def main():
    if len(sys.argv) != 4:
        print("Usage: python evaluate.py <binary> <stack_boundary.facts> <global_boundary.facts>")
        sys.exit(1)

    binary, stack_facts, global_facts = sys.argv[1], sys.argv[2], sys.argv[3]

    # Step 1: extract GT into stack_gt.tsv / global_gt.tsv next to this script
    out_dir = os.path.dirname(os.path.abspath(__file__))
    orig_dir = os.getcwd()
    os.chdir(out_dir)
    print(f"Extracting DWARF GT from: {binary}")
    extract_gt(binary)
    os.chdir(orig_dir)

    stack_gt_path  = os.path.join(out_dir, 'stack_gt.tsv')
    global_gt_path = os.path.join(out_dir, 'global_gt.tsv')

    # Step 2: load GT and predictions
    gt_stack  = load_stack(stack_gt_path)
    gt_global = load_global(global_gt_path)
    pred_stack  = load_stack(stack_facts)
    pred_global = load_global(global_facts)

    # Step 3: report
    result_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'result')
    os.makedirs(result_dir, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    result_file = os.path.join(result_dir, f"{os.path.basename(binary)}_{ts}.txt")

    with open(result_file, 'w') as out:
        header = f"Binary: {binary}\nTime: {datetime.now().isoformat()}\n"
        print(header); out.write(header + '\n')
        report("Local Variables (stack) — exact", pred_stack, gt_stack, out)
        report("Local Variables (stack) — offset match", pred_stack, gt_stack, out, use_stack_offset=True)
        report("Global Variables",        pred_global, gt_global, out, use_overlap=True)

    print(f"\n[compare] 结果已保存至: {result_file}")


if __name__ == '__main__':
    main()
