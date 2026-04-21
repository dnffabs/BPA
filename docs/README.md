# BPA-X 二进制程序分析 — 内存边界生成

## 项目概述

本项目实现了 BPA-X 论文中的**栈内存块边界**和**全局内存块边界**识别算法。

输入一个 ELF 二进制文件，输出：
- `stack_boundary.facts` — 每个函数的栈内存块边界（函数名、偏移量、大小）
- `global_boundary.facts` — 全局内存块边界（起始地址、大小）

## 快速开始

```bash
# 在 WSL 中运行
cd /mnt/c/Users/QC/Desktop/share/all/better/final
./pipeline/run.sh /path/to/binary
```

结果输出在 `build/<binary_name>_dir/facts/` 目录下。

## 项目结构

```
final/
├── pipeline/
│   ├── run.sh              # 统一入口
│   ├── preprocess.sh       # 阶段1：提取并过滤 VEX IR facts
│   └── boundary_gen.sh     # 阶段2：生成栈和全局边界
├── rules/
│   ├── preprocess.dl       # Soufflé：按函数范围过滤 VEX facts
│   ├── stack_boundary.dl   # Soufflé：栈边界识别
│   └── global_boundary.dl  # Soufflé：全局边界识别
├── tools/
│   ├── vex2Datalog/        # VEX IR → Datalog facts 转换器（angr）
│   ├── generate_facts.py   # 从二进制生成基础 facts
│   ├── getfuncinfo.py      # 提取 ELF 函数符号表
│   ├── gobal_info.py       # 提取 .data/.bss/.rodata 段信息
│   └── extract_global_addrs.py  # 预处理全局地址候选
└── docs/
    └── README.md
```

## 分析流水线

```
ELF 二进制
    │
    ▼ [generate_facts.py + angr]
基础 VEX IR facts (12 个文件)
    │
    ▼ [getfuncinfo.py + gobal_info.py]
addr_func.facts, data/bss/rodata.facts
    │
    ▼ [preprocess.dl — Soufflé]
filter_set_loc_vex.facts
filter_set_mem_vex.facts
filter_binop_vex_exp.facts
filtered_func.facts
    │
    ├─▶ [stack_boundary.dl — Soufflé]
    │       stack_boundary.facts
    │
    └─▶ [extract_global_addrs.py + global_boundary.dl]
            global_boundary.facts
```

## 输出格式

### stack_boundary.facts
```
<func_name>  <offset>  <size_bytes>
```
- `func_name`：函数名
- `offset`：相对于 RSP/RBP 的偏移（负数=局部变量，正数=参数）
- `size_bytes`：内存块大小（字节）

示例：
```
add     -8    8
main    -8    8
main     8    8
```

### global_boundary.facts
```
<addr>  <size_bytes>
```
- `addr`：全局内存块起始地址（十进制）
- `size_bytes`：内存块大小（字节）

示例：
```
4210704    32
4210736     8
```

## 算法说明

### 栈边界识别（stack_boundary.dl）

1. **识别栈指针 EID**：从 `get_loc_vex_exp` 找到 rsp/rbp 的实体 ID
2. **追踪临时变量**：`t = GET(rsp)` → t 持有栈指针值
3. **找偏移计算**：`binop(t, imm)` → 提取偏移量（Sub=负，Add=正）
4. **追踪地址传播**：偏移结果可能经过多次赋值才被用作 store 地址
5. **过滤内部地址**：若 offset2 落在 [offset1, offset1+size1) 内则删除

### 全局边界识别（global_boundary.dl）

1. **定义全局区间**：`.data`/`.bss`/`.rodata` 段范围
2. **收集候选地址**：VEX IR 中落在全局区间内的立即数
3. **计算 size**：相邻候选地址之差
4. **过滤内部地址**：若地址落在另一个地址的范围内则删除

## 环境依赖

- WSL (Ubuntu)
- Python 虚拟环境：`../venv/`（含 angr、pyelftools）
- Soufflé Datalog 引擎：`/usr/bin/souffle`

## 后续扩展规划

| 功能 | 状态 | 说明 |
|------|------|------|
| 栈边界识别 | ✅ 完成 | `rules/stack_boundary.dl` |
| 全局边界识别 | ✅ 完成 | `rules/global_boundary.dl` |
| 堆边界识别 | 待实现 | 基于 malloc/calloc/realloc 调用点 |
| CFG 构建 | 待实现 | 参考 `boundaryGen/new/cfg_gen.dl` |
| A-loc 生成 | 待实现 | 基于边界生成抽象内存位置 |
| 上下文敏感分析 | 待实现 | 需要调用图支持 |

### 堆边界识别（下一步）

参考 `boundaryGen/new/heap_mem_partition.dl`，需要：
1. 在 `preprocess.sh` 中提取 malloc/calloc/realloc 的调用点和返回地址
2. 新增 `rules/heap_boundary.dl`
3. 在 `boundary_gen.sh` 中添加调用步骤
