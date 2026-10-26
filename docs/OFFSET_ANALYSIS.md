# 块内偏移分析：实现、对照与验证

当前默认模式为 `--memory-model offset`。它在 BPA / BPA-X 风格的块模型上，加入 [BinPointer（CC 2022）](https://doi.org/10.1145/3497776.3517776) 启发的 0-base 偏移传播。本文对应 2026-10-26 的本地实现与回归结果。

基础的寄存器定义、分块、值传播和调用图不动点可先读 [块级基线推导](ALGORITHM_WALKTHROUGH.md)。本文解释默认模式新增的能力；本项目仍是依赖函数符号的研究原型。

## 1. 这次改善了什么

考虑 64 位程序中的两个函数指针字段：

```c
typedef int (*Callback)(void);
struct Pair { Callback first; Callback second; };

struct Pair *p = malloc(sizeof(*p));
p->first = alpha;
p->second = beta;
p->first();
```

令 `H` 表示该分配调用点对应的堆块。块级分析只记录 `H` 中包含 `{alpha, beta}`，读取 `first` 时两个地址都会出现。偏移模式把位置分开：

```text
p                  → H[0]
&p->first          → H[0]
&p->second         → H[8]
H[0..8)  保存       → &alpha
H[8..16) 保存       → &beta
读取 H[0..8)       → &alpha
间接调用候选        → {alpha}
```

32 位样例的字段步长为 4 字节。代码从二进制的访问宽度与常量位移得到这些信息，不读取 C 字段名来辅助主分析。可运行的样例是 [offset_heap_only.c](../tests/fixtures/offset_heap_only.c) 和包含三类内存的 [offset_fields.c](../tests/fixtures/offset_fields.c)。

## 2. 三种模式怎样对照

| 模式 | 堆 | 栈 / 全局 | 用途 |
| --- | --- | --- | --- |
| `block` | 位置未知 | 位置未知 | 块级对照基线 |
| `heap-offset` | 启用偏移 | 位置未知 | 检查单独细化堆的收益及限制 |
| `offset`（默认） | 启用偏移 | 启用可恢复偏移 | 当前完整偏移原型 |

三种模式使用相同前端、块划分和候选函数入口。块划分仍是每函数一帧块、每全局 section 一块、每堆分配调用点一块。`block` 是当前实现内的对照，不能当成原始 BPA 论文工具的实验成绩。

```bash
mkdir -p build/offset-demo
gcc -O0 -g -fno-pie -no-pie -fno-omit-frame-pointer \
    tests/fixtures/offset_heap_only.c -o build/offset-demo/fields

./build/offset-demo/fields

uv run --locked ./pipeline/run.sh build/offset-demo/fields \
    --memory-model block --output build/offset-demo/block
uv run --locked ./pipeline/run.sh build/offset-demo/fields \
    --memory-model heap-offset --output build/offset-demo/heap-offset
uv run --locked ./pipeline/run.sh build/offset-demo/fields \
    --memory-model offset --output build/offset-demo/offset
```

这个独立 64 位堆样例在块级模式得到 `{offset_alpha, offset_beta}`，另两种模式得到 `{offset_alpha}`。

## 3. 0-base 为什么能收敛

动态传播对指针采用以下规则，单位为字节：

| 操作 | 结果 | 原因 |
| --- | --- | --- |
| `q = p`，其中 `p → H[8]` | `q → H[8]` | 复制保留完整位置 |
| `p → H[0]`，计算 `p + 8` | `H[8]` | 从块起点执行一次常量位移 |
| `p → H[8]`，继续计算 `p + 8` | `H[unknown]` | 对内部指针继续位移时放宽 |
| 原始起点 `p → H[0]`，重新计算 `p + 16` | `H[16]` | 再次从起点计算，仍能区分 |
| `p → H[8]`，直接读取 `*p` | 读取 `H[8]` | 解引用不额外进行一次位移 |
| 位移不是已认证的字面常量 | `H[unknown]` | 避免把不完整的整数集合当成精确位移 |

本实现将 `+0/-0` 作为恒等运算，保留已有偏移。循环 `p += 8` 因而只需要有限的精确位置与未知位置，不会无限生成 `8、16、24……`。

已认证的栈仿射表达式和绝对全局地址可以由预分析直接给出精确位置。例如 `SP-32+8` 可以精确得到 entry-SP 的 `-24`，不必逐步执行上述动态放宽。预分析自己的数值集合上限仍为 8，完整性证明不覆盖未知输入与未证明的循环。

## 4. 读写怎样连接

主关系已扩展为：

```text
points_to_offset(eid, block, kind, offset)
memory_code_offset(block, kind, offset, size_bytes, code_address)
memory_pointer_offset(block, kind, offset, size_bytes,
                      target_block, target_kind, target_offset)
```

`kind` 为 `exact` 或 `unknown`。例如 `exact,8` 是精确位置，`unknown,0` 中的 0 只是占位，代表块内任意位置。负偏移合法，因此不用 `-1` 充当未知标志。完整字段说明见 [FACTS.md](FACTS.md)。

对于精确位置，读区间 `[r,r+size)` 与写区间 `[w,w+size)` 有交集才传播候选。未知位置的读匹配块内全部写，未知位置的写匹配块内全部读。精确字段的写入不会先合并成未知位置，再反向污染其它精确字段。

部分重叠、短读写以及未知位置可能无法完整重建一个指针。当前模型保留已有候选，并通过 `memory_unknown_offset` / `uncertain_call` 记录不确定性，尚未模拟任意指针的逐位组合。

`points_to.facts`、`memory_code.facts`、`memory_pointer.facts` 继续输出，但它们只是删除位置后的投影。例如看到 `memory_code(H,alpha)` 和 `memory_code(H,beta)`，并不能说明读取任意字段都会得到两者；应检查带偏移的关系。

## 5. 为什么额外检查预分析的完整性

原标量 / 栈预分析收集的是“已经算出来的可能值”。非空不代表所有来源都被处理过。例如：

```text
E 的输入 = {某栈地址, 整数 8}
R = E * 2

数值预分析可能只算出整数分支：R = {16}
```

若把 `{16}` 当成完整结果，可能错误限制后续传播。现在 `offset_model.py` 检查所有输入生产规则、依赖和输入组合是否均被支持。未知输入、load、调用输出、未支持的运算分支，以及未证明的循环都不能通过认证。

通过认证的栈地址才能替换通用偏移传播；未通过时继续保守分析。相关反例在 [test_offset_rules.py](../tests/test_offset_rules.py)。这一检查约束当前预分析的用法，不代表完整二进制语义都已建模。

## 6. 栈、全局和跨函数传播

**栈有两个坐标系。** `affine_stack` 相对于函数入口 SP；最终偏移相对于块起点。若帧块起点为 entry-SP 的 `-32`，表达式的 entry-SP 偏移为 `-24`，最终位置就是 `stk_f[8]`。块的观测跨度不用于排除未知位置。

**32 位位移与绝对地址分开解释。** `0xfffffffc` 作为 32 位位移表示 `-4`，作为绝对地址仍保留其高地址身份。未知 SP 对齐不猜测精确偏移。真实 `parameter_32` 回归中的 `main` 已不再出现约 4GB 的虚假跨度；对齐后的未知访问仍保守保留帧身份。

**全局初值**由 CLE 应用重定位后的内存生成，记录相对于 section 起点的精确偏移。全局块仍按 section 划分；对非零内部指针继续算术时可能退化。初始化指针扫描仅覆盖对齐的机器字。

**寄存器实参和返回值**携带完整的目标块与偏移。内存中保存的指针也保留目标偏移，因而可以处理：

```text
分配 Pair → 取第二个字段地址 H[8] → 函数返回 H[8]
         → 存进另一个堆对象 → 再读出 H[8]
         → 作为参数传给 invoke_slot → 只读取 beta
```

32 位和 64 位跨函数样例均已验证该链路，源码为 [offset_interproc.c](../tests/fixtures/offset_interproc.c)。

**栈参数**现在结合认证 SP 和调用点到达写入快照逐槽映射，能够区分不同参数位置及同一槽在不同调用前的写入。原 32 位内部指针样例的额外目标已消除。未知 SP、动态别名、输入参数区域仍保守处理；上下文仍合并。公式、延迟 SP 修复和快照边界见 [STACK_ARGUMENTS.md](STACK_ARGUMENTS.md)。

**内存库函数摘要**暂将目的存储位置退化为未知，保留复制值中的指针目标偏移。`memcpy` 的复制范围与位置平移、`realloc` 保留前缀等尚未细化。

## 7. 为什么仅细化堆仍会出现误差

在混合字段样例中，局部变量 `pair` 与保存的调用者帧指针都位于粗粒度栈块。仅启用堆偏移时，读取 `pair` 可能同时得到：

```text
真实指针：H[0]
假别名：  调用者栈帧[unknown]
```

随后两个字段的写入都可能落到这个假的栈位置。最终读取同时走精确堆位置与粗栈位置，仍会带入 `beta`。测试既断言该模式仍得到 `{alpha,beta}`，也检查堆中的写入确实分开在 `0` 与 `sizeof(Callback)`。

独立堆样例去掉了这个干扰，验证仅堆偏移可以消除那一例的额外候选；默认模式进一步区分栈位置后，混合样例的三个间接调用也能精确区分。这解释了完整传播链中每一段抽象精度的重要性。

## 8. 完整验证与实测结果

在配置好 uv、Soufflé 和 32 位编译 / 运行环境后：

```bash
uv run --locked python tests/run_all.py
```

本轮环境为 Python 3.12.15、angr 9.2.173、GCC 13.3、Soufflé 2.5；原生样例使用 `-O0 -g`，禁用内联、尾调用优化和栈保护，保留帧指针。基础回归额外包含 AMD64 PIE。

| 测试组 | 测试方法数 | 检查内容 |
| --- | ---: | --- |
| 基础语义 / 原生流程 | 7 | 17 次 X86 / AMD64 / PIE 分析，SSA、参数、内存与错误输入 |
| 32/64 位预分析 | 5 | 负位移、连续运算、溢出、转换、对齐与栈跨度 |
| 偏移规则反例 | 10 | 0-base、循环、合流完整性、AND 对称传播、未知位置、部分访问与内部指针 |
| 资源统计 | 2 | 子进程峰值不混入大父进程；缺少 GNU time 时返回未知指标 |
| 栈参数映射 / 写入快照 | 11 | 位置、分支、复用、部分覆盖、未知回退、递归、槽逃逸及延迟 SP |
| 偏移原生对照 | 6 | 11 个二进制 × 3 模式，共 33 次分析 |
| **合计** | **41** | **全部通过，无跳过项** |

偏移对照中，每种模式分析相同的 21 个间接调用点。TP / FP / FN 相对于样例预设目标统计，循环位置可有两个预期目标，因此 TP 可以大于调用点数。

| 模式 | TP | FP | FN | 间接调用边 | 11 次流水线总耗时 | 求解命令总耗时 | 单次最大峰值 RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `block` | 23 | 19 | 0 | 42 | 16.5636 s | 1.4936 s | 15,792 KiB |
| `heap-offset` | 23 | 18 | 0 | 41 | 16.4337 s | 1.4502 s | 15,932 KiB |
| `offset` | 23 | 2 | 0 | 25 | 16.1757 s | 1.3968 s | 15,692 KiB |

时间为一次运行的记录，小样例差异不能证明性能优劣或大型程序可扩展性。峰值只统计最终 Soufflé 求解命令及预处理器，取 11 次中的最大值；它不包含完整 Python / angr 流水线。测量通过可选 Linux GNU time 完成，缺失时为 `null`。

上一版直接对 angr 的子进程使用 `wait4`，会混入 fork 后 exec 前继承的父进程内存峰值，曾得到约 130MB 的误导性结果。本轮已修正测量，并加入大父进程 / 小子进程反例验证。

默认模式剩余 2 个 FP 的来源：

- 同字段覆盖：32 位和 64 位各一个。先写 `alpha` 再写 `beta`，弱更新仍保留二者。

三类字段分离在默认模式均精确；循环指针放宽后仍找到两种预期目标。FN 为 0 只描述本测试集，不能解释成任意输入的 soundness 保证。

结果文件位于：

```text
build/validation/results.json          # 41项验证状态、失败详情、版本与总览
build/regressions/results.json         # 17次基础原生分析（本轮TP34、FP7、FN0）
build/offset-regressions/results.json   # 33次模式对照、逐调用目标与性能
```

`tests/test_offsets.py` 只在全部预期分析完成且断言通过后把报告标为 `completed`。单独只运行部分测试时，其报告会明确标记不完整。所有 build 产物均不提交。

## 9. 接下来可研究的改进

当前成果是 VEX 上的偏移分析原型，尚未完整复现 BinPointer 的全部实现与评估。可继续按误差来源推进：

1. 继续完善未知 SP、特殊调用约定和跨函数调用上下文；普通调用的认证 SP 映射及调用点栈写入快照已落地。
2. 在明确的对象身份、别名与执行顺序条件下研究内存流敏感性 / 强更新，处理同字段覆盖。
3. 细化内存函数复制范围与目的偏移，加入相应反例。
4. 用更多优化等级、更大程序和动态轨迹评估精度、时间、内存及遗漏；单列上游恢复失败与值传播误差。
5. 在可控基线上研究与间接调用相关位置的选择性偏移跟踪，并验证退化策略。
