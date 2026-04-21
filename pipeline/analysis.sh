#!/bin/bash
# analysis.sh — 阶段5：值集分析（不动点迭代，解析间接调用）
# 用法: ./analysis.sh <binary_file> <base_dir>
set -e

BASE_DIR="$2"
FACTS_DIR="$BASE_DIR/facts"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOLS_DIR="$ROOT_DIR/tools"
RULES_DIR="$ROOT_DIR/rules"
VENV_PY="$ROOT_DIR/../venv/bin/python"

echo "[analysis] 开始值集分析..."

# 预处理：找出立即数中等于函数起始地址的 EID
echo "[analysis] 提取函数地址 EID..."
"$VENV_PY" "$TOOLS_DIR/extract_imm_func_eid.py" "$FACTS_DIR" \
    -o "$FACTS_DIR/imm_func_addr_eid.facts"

# 运行值集分析（Soufflé 自动完成不动点迭代）
echo "[analysis] 运行 analysis.dl..."
souffle -F "$FACTS_DIR" -D "$FACTS_DIR" "$RULES_DIR/analysis.dl"

echo "[analysis] 完成"
echo "[analysis] 值集: $FACTS_DIR/value_set.facts"
echo "[analysis] 间接调用目标: $FACTS_DIR/indirect_call_target.facts"
