#!/bin/bash
# run.sh — 统一入口：完整分析流水线
# 用法: ./run.sh <binary_file>
set -e

if [ "$#" -ne 1 ]; then
    echo "用法: $0 <binary_file>"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BINARY_FILE="$(realpath "$1")"
BASE_NAME="$(basename "$BINARY_FILE")"
BASE_DIR="$ROOT_DIR/build/${BASE_NAME}_dir"
FACTS_DIR="$BASE_DIR/facts"

mkdir -p "$FACTS_DIR"

echo "========================================="
echo "[run] 二进制: $BINARY_FILE"
echo "[run] 输出目录: $BASE_DIR"
echo "========================================="

chmod +x "$SCRIPT_DIR"/*.sh

# 计时 + 内存辅助函数
# /usr/bin/time -v 输出峰值内存；macOS 用 -l
_time_cmd() {
    local label="$1"; shift
    local start end elapsed mem_kb
    start=$(date +%s%3N)
    if /usr/bin/time -v "$@" 2>/tmp/_run_time_out; then
        :
    else
        cat /tmp/_run_time_out >&2
        return 1
    fi
    end=$(date +%s%3N)
    elapsed=$(( end - start ))
    mem_kb=$(grep -i 'maximum resident' /tmp/_run_time_out | awk '{print $NF}')
    printf "[time] %-20s  时间: %d.%03ds  峰值内存: %s KB\n" \
        "$label" $(( elapsed/1000 )) $(( elapsed%1000 )) "${mem_kb:-N/A}"
}

TOTAL_START=$(date +%s%3N)

echo
_time_cmd preprocess    "$SCRIPT_DIR/preprocess.sh"   "$BINARY_FILE" "$BASE_DIR"
echo
_time_cmd boundary_gen  "$SCRIPT_DIR/boundary_gen.sh" "$BINARY_FILE" "$BASE_DIR"
echo
_time_cmd cfg           "$SCRIPT_DIR/cfg.sh"          "$BINARY_FILE" "$BASE_DIR"
echo
_time_cmd ssa           "$SCRIPT_DIR/ssa.sh"          "$BINARY_FILE" "$BASE_DIR"
echo
_time_cmd analysis      "$SCRIPT_DIR/analysis.sh"     "$BINARY_FILE" "$BASE_DIR"
echo
_time_cmd compare       "$SCRIPT_DIR/compare.sh"      "$BINARY_FILE" "$BASE_DIR"

TOTAL_END=$(date +%s%3N)
TOTAL_MS=$(( TOTAL_END - TOTAL_START ))

echo
echo "========================================="
echo "[run] 分析完成！结果在: $FACTS_DIR"
echo "  stack_boundary.facts      — 栈内存块边界"
echo "  global_boundary.facts     — 全局内存块边界"
echo "  heap_boundary.facts       — 堆内存块边界"
echo "  stack/global/heap_aloc    — A-loc"
echo "  cfg_node/edge/call_graph  — CFG + 调用图"
echo "  ssa_def/use/phi_node      — SSA"
echo "  value_set.facts           — 值集"
echo "  indirect_call_target.facts — 间接调用解析"
printf "[run] 总耗时: %d.%03ds\n" $(( TOTAL_MS/1000 )) $(( TOTAL_MS%1000 ))
echo "========================================="
