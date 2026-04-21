#!/bin/bash
# cfg.sh — 阶段3：构建控制流图
# 用法: ./cfg.sh <binary_file> <base_dir>
set -e

BINARY_FILE="$1"
BASE_DIR="$2"
FACTS_DIR="$BASE_DIR/facts"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOLS_DIR="$ROOT_DIR/tools"
RULES_DIR="$ROOT_DIR/rules"
VENV_PY="$ROOT_DIR/../venv/bin/python"

echo "[cfg] 开始构建 CFG..."

# 1) 用 angr 提取 CFG 边
echo "[cfg] 提取 CFG 边..."
"$VENV_PY" "$TOOLS_DIR/extract_cfg_angr.py" "$BINARY_FILE" "$FACTS_DIR"

# 2) 运行 Soufflé CFG 规则
echo "[cfg] 运行 cfg.dl..."
souffle -F "$FACTS_DIR" -D "$FACTS_DIR" "$RULES_DIR/cfg.dl"

echo "[cfg] 完成"
echo "[cfg] CFG 节点: $FACTS_DIR/cfg_node.facts"
echo "[cfg] CFG 边:   $FACTS_DIR/cfg_edge.facts"
echo "[cfg] 调用图:   $FACTS_DIR/call_graph.facts"
