# 运行环境

已验证：Linux、Python 3.12.3、GCC 13.3、angr/pyvex/archinfo 9.2.173、pyelftools 0.31、Soufflé 2.5（64 位 word）。

## 必需

- Python 虚拟环境中的 `requirements.txt` 依赖。
- `bash`、Soufflé。
- 回归测试需要 GCC 与可用的 32/64 位 libc 开发环境；只分析已有二进制不需要重新编译。
- 输入为 Linux AMD64/X86 ELF，主流程当前需要函数 `.symtab`。
- DWARF 仅用于可选的边界评估。

本机 `.venv` 复用研究工作区中已安装的 BPA-X 环境，没有重新下载依赖。换机创建 `.venv` 后按 requirements 安装；不要把本机的环境链接提交到 Git。

`BPA_PYTHON` 可覆盖解释器，`SOUFFLE` 可覆盖引擎路径。compare 与主分析使用同一个 Python。

Shell 阶段脚本可直接执行；单独调用某个阶段会先执行其所有前置步骤：

```bash
./pipeline/ssa.sh /path/to/program /path/to/output
```

默认输出目录包含输入绝对路径的哈希，避免不同位置的同名程序冲突。每次全量运行重新提取 facts，不根据“文件非空”复用旧内容。相同输出目录使用文件锁串行化，执行状态和二进制 SHA256 记录在 summary.json。
