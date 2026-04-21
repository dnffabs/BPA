#!/bin/bash
# preprocess.sh — 阶段1：提取 VEX IR facts 并按函数范围过滤
# 用法: ./preprocess.sh <binary_file> <base_dir>
set -e

BINARY_FILE="$1"
BASE_DIR="$2"
FACTS_DIR="$BASE_DIR/facts"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOLS_DIR="$ROOT_DIR/tools"
RULES_DIR="$ROOT_DIR/rules"
VENV_PY="$ROOT_DIR/../venv/bin/python"

mkdir -p "$FACTS_DIR"

echo "[preprocess] 开始预处理: $BINARY_FILE"

# 1) 生成基础 VEX IR facts（如已存在则跳过）
REQUIRED=(binop_vex_exp.facts set_loc_vex.facts set_mem_vex.facts get_loc_vex_exp.facts
          get_mem_vex_exp.facts imm_vex_exp.facts exit_vex_exp.facts irsbImark.facts
          jmp_vex_exp.facts call_vex_exp.facts ret_vex_exp.facts unop_vex_exp.facts)
NEED_GEN=false
for f in "${REQUIRED[@]}"; do
    [ ! -s "$FACTS_DIR/$f" ] && NEED_GEN=true && break
done
if $NEED_GEN; then
    echo "[preprocess] 生成 VEX IR facts..."
    "$VENV_PY" "$TOOLS_DIR/generate_facts.py" "$BINARY_FILE" -o "$FACTS_DIR"
fi

# 2) 提取函数符号表
echo "[preprocess] 提取函数信息..."
"$VENV_PY" "$TOOLS_DIR/getfuncinfo.py" "$BINARY_FILE" -o "$FACTS_DIR/addr_func.facts"

# 3) 提取段信息（.data/.bss/.rodata）
echo "[preprocess] 提取段信息..."
"$VENV_PY" "$TOOLS_DIR/gobal_info.py" "$BINARY_FILE" --outdir "$FACTS_DIR"

# 4) 生成 compiler_build_in.facts（编译器/运行时内建函数，排除出分析范围）
echo "[preprocess] 生成 compiler_build_in.facts..."
"$VENV_PY" "$TOOLS_DIR/gen_compiler_builtin.py" "$FACTS_DIR/addr_func.facts" \
    -o "$FACTS_DIR/compiler_build_in.facts"
echo "[preprocess] 运行 preprocess.dl..."
souffle -F "$FACTS_DIR" -D "$FACTS_DIR" "$RULES_DIR/preprocess.dl"

echo "[preprocess] 完成"
