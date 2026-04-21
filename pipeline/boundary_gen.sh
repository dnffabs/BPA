#!/bin/bash
# boundary_gen.sh — 阶段2：生成栈和全局内存边界
# 用法: ./boundary_gen.sh <binary_file> <base_dir>
set -e

BINARY_FILE="$1"
BASE_DIR="$2"
FACTS_DIR="$BASE_DIR/facts"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOLS_DIR="$ROOT_DIR/tools"
RULES_DIR="$ROOT_DIR/rules"
VENV_PY="$ROOT_DIR/../venv/bin/python"

echo "[boundary_gen] 开始生成边界..."

# 1) 预处理立即数为有符号值（避免 Soufflé 64 位补码溢出）
echo "[boundary_gen] 预处理立即数..."
"$VENV_PY" "$TOOLS_DIR/extract_imm_signed.py" "$FACTS_DIR/imm_vex_exp.facts" \
    -o "$FACTS_DIR/imm_signed.facts"

# 2) 生成全局地址候选
echo "[boundary_gen] 提取全局地址候选..."
"$VENV_PY" "$TOOLS_DIR/extract_global_addrs.py" "$FACTS_DIR" \
    -o "$FACTS_DIR/global_addr_candidates.facts"

# 2) 生成栈边界
echo "[boundary_gen] 运行 stack_boundary.dl..."
souffle -F "$FACTS_DIR" -D "$FACTS_DIR" "$RULES_DIR/stack_boundary.dl"

# 3) 生成全局边界
echo "[boundary_gen] 运行 global_boundary.dl..."
souffle -F "$FACTS_DIR" -D "$FACTS_DIR" "$RULES_DIR/global_boundary.dl"

# 4) 生成全局地址 EID 映射（避免 Soufflé to_number 溢出）
echo "[boundary_gen] 提取全局地址 EID 映射..."
"$VENV_PY" "$TOOLS_DIR/extract_imm_global_eid.py" "$FACTS_DIR" \
    -o "$FACTS_DIR/imm_global_eid.facts"

# 5) 生成 A-loc 并映射内存访问
echo "[boundary_gen] 运行 aloc_gen.dl..."
souffle -F "$FACTS_DIR" -D "$FACTS_DIR" "$RULES_DIR/aloc_gen.dl"

# 6) 提取堆分配调用点
echo "[boundary_gen] 提取堆分配调用点..."
"$VENV_PY" "$TOOLS_DIR/extract_heap_calls.py" "$BINARY_FILE" "$FACTS_DIR" \
    -o "$FACTS_DIR/heap_alloc_call.facts"

# 7) 生成堆边界和堆 A-loc
echo "[boundary_gen] 运行 heap_boundary.dl..."
souffle -F "$FACTS_DIR" -D "$FACTS_DIR" "$RULES_DIR/heap_boundary.dl"

echo "[boundary_gen] 完成"
echo "[boundary_gen] 栈边界: $FACTS_DIR/stack_boundary.facts"
echo "[boundary_gen] 全局边界: $FACTS_DIR/global_boundary.facts"
echo "[boundary_gen] 堆边界: $FACTS_DIR/heap_boundary.facts"
echo "[boundary_gen] 栈 A-loc: $FACTS_DIR/stack_aloc.facts"
echo "[boundary_gen] 全局 A-loc: $FACTS_DIR/global_aloc.facts"
echo "[boundary_gen] 堆 A-loc: $FACTS_DIR/heap_aloc.facts"
