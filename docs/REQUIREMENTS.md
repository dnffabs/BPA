# BPA-X Final 迁移 Requirements

## 目的

本文档用于将 `c:\Users\QC\Desktop\share\all\better\final` 迁移到另一台机器，并确保项目可以正常运行以下完整流程：

- `preprocess.sh`：生成并过滤 VEX facts
- `boundary_gen.sh`：生成栈 / 全局 / 堆边界
- `cfg.sh`：构建 CFG 与调用图
- `ssa.sh`：生成 SSA
- `analysis.sh`：值集分析与间接调用目标解析
- `compare.sh`：提取 DWARF GT 并输出 Precision / Recall / F1

## 最低系统要求

- 操作系统：
  - 推荐 `Ubuntu 22.04+` 或其他主流 Linux
  - Windows 推荐通过 `WSL2 + Ubuntu` 运行
- CPU 架构：
  - 推荐 `x86_64`
- Python：
  - 推荐 `Python 3.10 - 3.12`
- Shell：
  - 需要 `bash`

## 必需系统依赖

以下工具必须在目标机器可执行：

- `python3`
- `pip`
- `bash`
- `gcc`
- `make`
- `souffle`
- `/usr/bin/time`
- `realpath`

建议安装命令（Ubuntu / WSL）：

```bash
sudo apt update
sudo apt install -y \
  python3 python3-pip python3-venv \
  build-essential make gcc \
  coreutils time \
  souffle
```

说明：

- `souffle` 是整个 Datalog 分析流水线的核心依赖。
- `gcc` / `make` 用于编译 `pipeline/bin/` 中的测试程序，或编译新的样例二进制。
- `/usr/bin/time` 被 [run.sh](file:///c:/Users/QC/Desktop/share/all/better/final/pipeline/run.sh) 用于统计运行时间和峰值内存。

## 必需 Python 依赖

根据当前代码实际导入情况，项目至少需要以下 Python 包：

- `angr`
- `pyelftools`

建议安装到项目外层虚拟环境：

- 代码中多个脚本使用固定路径：
  - `ROOT_DIR/../venv/bin/python`
- 也就是说，对 `final/` 而言，虚拟环境默认应放在：
  - `better/venv`

推荐创建方式：

```bash
cd /path/to/better
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install angr pyelftools
```

## compare 阶段的额外 Python 依赖

如果只跑主分析流程，通常只需要：

- `angr`
- `pyelftools`

如果还要运行 `compare.sh` 或 `compare/` 下的扩展脚本，建议额外安装：

- `networkx`
- `matplotlib`
- `pyvex`
- `claripy`
- `capstone`
- `psutil`

推荐一次性安装：

```bash
pip install networkx matplotlib pyvex claripy capstone psutil
```

注意：

- [compare.sh](file:///c:/Users/QC/Desktop/share/all/better/final/pipeline/compare.sh) 当前直接调用 `python3`，不是固定走 `venv/bin/python`。
- 因此你有两种选择：
  - 先 `source ../venv/bin/activate` 后再运行整个流程
  - 或把这些包也安装到系统 Python 中

推荐做法是：

```bash
cd /path/to/better
source venv/bin/activate
cd final
./pipeline/run.sh ./pipeline/bin/simple_test
```

## 二进制输入要求

项目默认分析 ELF 二进制，因此目标程序应满足：

- 文件格式：`ELF`
- 平台：优先支持 Linux `x86_64`
- 建议关闭 PIE：
  - `-fno-pie -no-pie`
- 建议保留帧指针：
  - `-fno-omit-frame-pointer`
- 如需进行 `compare` 阶段 DWARF GT 抽取，建议保留调试信息：
  - `-g`

推荐编译参数：

```bash
gcc -O0 -g -fno-omit-frame-pointer -fno-pie -no-pie -o simple_test simple_test.c
```

## 目录约定

迁移后应保持如下关键目录结构：

```text
better/
├── venv/                 # Python 虚拟环境，final 脚本默认依赖它
└── final/
    ├── pipeline/
    ├── rules/
    ├── tools/
    ├── compare/
    ├── docs/
    └── build/            # 运行时自动生成分析结果
```

其中：

- `final/build/` 是运行产物目录，不需要纳入版本管理
- `final/compare/result/` 是对比实验结果目录，也不需要纳入版本管理
- 当前 `.gitignore` 已忽略这两个目录

## 迁移步骤

### 1. 拷贝源码目录

将以下目录完整拷贝到目标机器：

- `final/pipeline`
- `final/rules`
- `final/tools`
- `final/compare`
- `final/docs`
- `final/.gitignore`

不需要拷贝：

- `final/build`
- `final/compare/result`

### 2. 准备 Python 虚拟环境

在 `better/` 根目录创建虚拟环境：

```bash
cd /path/to/better
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install angr pyelftools networkx matplotlib pyvex claripy capstone psutil
```

### 3. 检查 Souffle

确认可执行：

```bash
souffle --version
```

### 4. 检查 Python 依赖

```bash
cd /path/to/better
source venv/bin/activate
python -c "import angr, elftools; print('python deps ok')"
```

### 5. 编译测试二进制

项目自带测试二进制位于：

- `final/pipeline/bin/simple_test`
- `final/pipeline/bin/bzip2`
- `final/pipeline/bin/hmmer`

如果需要重新编译，可使用：

```bash
cd /path/to/better/final/pipeline/bin
make
```

### 6. 运行完整流程

```bash
cd /path/to/better
source venv/bin/activate
cd final
./pipeline/run.sh ./pipeline/bin/simple_test
```

输出结果位于：

```text
final/build/simple_test_dir/facts/
```

## 运行成功的判定标准

成功运行后，以下文件应存在于 `final/build/<binary>_dir/facts/` 中：

- `addr_func.facts`
- `filtered_func.facts`
- `cfg_node.facts`
- `cfg_edge.facts`
- `call_graph.facts`
- `stack_boundary.facts`
- `global_boundary.facts`
- `heap_boundary.facts`
- `ssa_def.facts`
- `ssa_use.facts`
- `phi_node.facts`
- `value_set.facts`
- `indirect_call_target.facts`

如果运行了 `compare.sh`，还会在以下目录看到结果：

```text
final/compare/result/
```

## 已知注意事项

### 1. compare.sh 使用的是 `python3`

[compare.sh](file:///c:/Users/QC/Desktop/share/all/better/final/pipeline/compare.sh) 当前调用：

```bash
python3 "$COMPARE_DIR/evaluate.py" ...
```

因此：

- 若未先激活虚拟环境，可能出现缺包
- 迁移后建议统一先执行：

```bash
source /path/to/better/venv/bin/activate
```

### 2. 仅支持 Linux/WSL 风格路径

当前脚本以 bash + Linux 工具链为主，不建议直接在 Windows 原生命令行运行。

### 3. 输入二进制最好带调试信息

若要使用 `compare/` 中的 DWARF GT 提取功能，二进制应尽量保留：

- DWARF 调试信息
- 符号表

否则评估阶段可能无法正确提取 GT。

## 建议的迁移后自检命令

```bash
cd /path/to/better
source venv/bin/activate

souffle --version
python -c "import angr, elftools; print('ok')"

cd final
./pipeline/run.sh ./pipeline/bin/simple_test
ls -l ./build/simple_test_dir/facts | head
```

## 建议保留的机器环境信息

为了便于后续复现，建议在目标机器记录：

- `python3 --version`
- `pip freeze`
- `souffle --version`
- `gcc --version`
- `uname -a`

可以保存为：

```bash
mkdir -p final/docs/env
python3 --version > final/docs/env/python_version.txt
pip freeze > final/docs/env/pip_freeze.txt
souffle --version > final/docs/env/souffle_version.txt
gcc --version > final/docs/env/gcc_version.txt
uname -a > final/docs/env/uname.txt
```

