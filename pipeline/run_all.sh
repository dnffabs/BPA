#!/bin/bash
# run_all.sh — 批量分析二进制文件
# 用法:
#   ./run_all.sh              # 分析 bin/ 目录下所有文件
#   ./run_all.sh <dir>        # 分析指定目录下所有文件
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${1:-$SCRIPT_DIR/bin}"

if [ ! -d "$BIN_DIR" ]; then
    echo "错误: 目录不存在: $BIN_DIR"
    exit 1
fi

BINARIES=()
while IFS= read -r -d '' f; do
    # 跳过非 ELF 文件（脚本、文本等）
    if file "$f" | grep -q 'ELF'; then
        BINARIES+=("$f")
    fi
done < <(find "$BIN_DIR" -maxdepth 1 -type f -print0)

if [ ${#BINARIES[@]} -eq 0 ]; then
    echo "未找到 ELF 二进制文件: $BIN_DIR"
    exit 1
fi

echo "========================================="
echo "[run_all] 共找到 ${#BINARIES[@]} 个二进制文件"
echo "========================================="

PASS=0; FAIL=0
for BIN in "${BINARIES[@]}"; do
    echo
    echo ">>> $(basename "$BIN")"
    if "$SCRIPT_DIR/run.sh" "$BIN"; then
        PASS=$((PASS+1))
    else
        echo "[run_all] 失败: $BIN"
        FAIL=$((FAIL+1))
    fi
done

echo
echo "========================================="
echo "[run_all] 完成: 成功=$PASS  失败=$FAIL"
echo "========================================="
