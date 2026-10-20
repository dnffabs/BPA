# 环境配置与故障排查

主运行方式见根目录 [README](../README.md)。Python 版本请求在 `.python-version`，依赖约束在 `pyproject.toml`，可复现的依赖解析结果在 `uv.lock`。

## 系统依赖

- Linux x86_64，或 Windows 上的 WSL2。
- Soufflé 2.5（已验证），64 位 word；安装步骤见 [官方文档](https://souffle-lang.github.io/install)。
- Bash；Git、curl 用于获取代码和安装 uv；file 用于批量入口识别 ELF。
- GCC / binutils 用于回归测试。已验证 GCC 13.3。
- 完整回归需要 32 位 libc 开发环境和宿主机的 32 位执行支持。

Ubuntu / Debian：

```bash
sudo apt update
sudo apt install -y git curl build-essential binutils file
sudo apt install -y gcc-multilib libc6-dev-i386
```

Soufflé 应单独按照官方发行包或源码构建说明安装，不假定默认 apt 源中存在适用版本。安装后运行 `souffle --version` 检查版本与 word size。

## uv 环境

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"

# 在项目根目录执行
uv python install 3.12
uv sync --locked
uv run --locked python --version
uv run --locked python -c "import angr, elftools; print('Python dependencies ready')"
```

项目选择 Python 3.12 系列；需要精确到补丁版本时，通过 `uv python pin` 写入完整版本号。Python 版本与依赖版本各由独立文件管理，`uv.lock` 不代替解释器版本请求。

直接依赖：angr 9.2.173、pyelftools 0.31、setuptools 80.9.0。后者用于兼容 Unicorn 对 `pkg_resources` 的导入。requirements.txt 为 uv 导出的兼容文件，不作为第二份手工依赖声明。

`pyproject.toml` 还约束 `bitstring<5` 与 `pycparser<3`，用于保留当前 angr / pyvex 使用的 API。这些兼容约束随锁文件一起解析，不能只安装未锁定的 angr 后假定环境等价。

解释器选择顺序：显式 `BPA_PYTHON` → uv 项目环境 → 已存在的项目 `.venv`。推荐通过 `uv run --locked` 运行，确保环境与锁文件一致。

## 配置 Soufflé

默认从 PATH 查找，也可显式指定：

```bash
export SOUFFLE=/absolute/path/to/souffle
uv run --locked ./pipeline/run.sh /path/to/program --output build/program-analysis
```

研究工作区中原有的 Soufflé 回退路径仅用于兼容；公开使用时应将引擎加入 PATH 或设置 `SOUFFLE`。

## 常见问题

### `uv` 找不到

重新打开终端，或把安装目录加入 PATH。默认 Linux 用户安装路径为 `$HOME/.local/bin`，自定义路径以实际安装配置为准。

### `uv sync --locked` 报锁文件不匹配

如果只运行仓库代码，确认 `pyproject.toml` 与 `uv.lock` 来自同一提交。如果主动修改依赖，先运行 `uv lock`，再 `uv sync --locked`，并重新运行回归。

### 从旧的共享环境迁移

旧部署曾将 `.venv` 链接到另一个项目的虚拟环境。迁移前先确认 `ls -ld .venv` 显示的是链接；仅在确认是链接时运行 `unlink .venv`，然后 `uv sync --locked` 创建独立环境。不要对链接指向的目录进行递归删除。

### 缺少 `.symtab`

主分析当前需要定义函数的符号信息。使用未执行完全 strip 的 ELF；DWARF 与 `.symtab` 的职责不同，仅保留 DWARF 不能替代函数符号。

### 没有 DWARF

默认主分析仍可运行。`--compare` 会明确跳过无 DWARF 的评估。自行编译用于评估的样例时加 `-g`。

### `gcc -m32` 编译失败

检查是否安装 multilib 与 32 位 libc 开发包。仅分析已有二进制时不需要本地重新编译。

### 32 位程序运行出现 SIGSYS

部分执行沙箱限制 32 位系统调用。请在支持 x86 执行的 Linux / WSL2 普通终端运行完整回归；该错误发生在原生程序执行阶段，不能作为分析结果。

### 看到 `pkg_resources` 弃用提示

这是当前固定的 Unicorn 依赖产生的提示。setuptools 保持在项目锁定的版本；以命令退出码、summary.json 和测试结果判断运行状态。

## 输出隔离

默认输出目录包含输入绝对路径的哈希，避免不同位置的同名程序冲突。每次运行重新生成 facts，相同输出目录通过文件锁串行化。输入 SHA256、阶段耗时与执行状态写入 summary.json。

`--compare` 的 GT 和报告保存在该次输出目录，不覆盖源码中的历史 GT。
