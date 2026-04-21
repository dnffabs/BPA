#!/bin/bash
# ssa.sh — 阶段4：SSA 变换（架构寄存器）
# 用法: ./ssa.sh <binary_file> <base_dir>
set -e

BASE_DIR="$2"
FACTS_DIR="$BASE_DIR/facts"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RULES_DIR="$ROOT_DIR/rules"

echo "[ssa] 运行 ssa.dl..."
souffle -F "$FACTS_DIR" -D "$FACTS_DIR" "$RULES_DIR/ssa.dl"

echo "[ssa] 完成"
echo "[ssa] SSA 定义: $FACTS_DIR/ssa_def.facts"
echo "[ssa] SSA 使用: $FACTS_DIR/ssa_use.facts"
echo "[ssa] φ 节点:   $FACTS_DIR/phi_node.facts"
