#!/bin/bash
# compare.sh — 对比实验：提取 DWARF GT 并计算 Precision/Recall/F1
# 用法: ./compare.sh <binary_file> <base_dir>
set -e

BINARY_FILE="$(realpath "$1")"
BASE_DIR="$2"
FACTS_DIR="$BASE_DIR/facts"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPARE_DIR="$SCRIPT_DIR/../compare"

echo "========================================="
echo "[compare] 开始对比实验"
echo "[compare] 二进制: $BINARY_FILE"
echo "[compare] facts 目录: $FACTS_DIR"
echo "========================================="

python3 "$COMPARE_DIR/evaluate.py" \
    "$BINARY_FILE" \
    "$FACTS_DIR/stack_boundary.facts" \
    "$FACTS_DIR/global_boundary.facts"
