# 跨函数栈参数：SP 换算、调用点快照与验证

本文对应 offset 扩展 v2，记录 2026-10-26 的实现与验证。默认 `--memory-model offset` 在可认证时逐槽传递栈参数；`block`、`heap-offset` 保持粗粒度栈对照。

## 1. 需要同时解决两个问题

考虑 32 位程序：

```c
int invoke(Callback first, Callback second) {
    return first();
}

invoke(alpha, beta);
```

分析需要知道哪两个物理栈位置对应 `first` 和 `second`，还需要知道这些位置在**这次调用前**保存的值。只恢复槽位置，仍会把复用同一槽的多次写入混合。

现在使用两步：

1. 通过调用前 SP，把调用者的写入位置换算成被调函数的参数位置。
2. 对已认证本地栈写入，沿函数内 CFG 找出仍能到达这次调用的定义；传入这些写入表达式对应的值。

普通堆、全局以及一般栈 load/store 仍采用流不敏感弱更新。新增的执行顺序信息专门用于栈传参。

## 2. 从一个地址换算到另一个坐标系

设调用者函数入口 SP 为 `S`，调用前 SP 为 `S+d`，机器字大小为 `w`。普通 CALL 将返回地址压入栈：

```text
被调函数入口 SP = S+d-w
```

调用者 entry-SP 偏移 `x` 对应的真实地址为 `S+x`，相对于被调函数入口的位置为：

```text
callee_entry_offset = (S+x) - (S+d-w) = x-d+w
```

32 位例子，`d=-32`、`w=4`：

| 内容 | 调用者 entry-SP 偏移 x | 被调者 entry-SP 偏移 x-d+w |
| --- | ---: | ---: |
| 第一个参数 alpha | -32 | +4 |
| 第二个参数 beta | -28 | +8 |
| CALL 压入的返回地址 | -36 | 0 |

最后还要转换成块内偏移。若调用者块起点为 `bs`，源块内偏移为 `o`，被调者块起点为 `cs`：

```text
dest_block_offset = bs+o-d+w-cs
```

映射保留写入宽度，并检查它是否与被调方实际读取的参数区间重叠。64 位 AMD64 SysV 使用相同公式，`w=8`；前六个整数/指针参数走寄存器，第七、八个参数可以用这个栈映射处理。

## 3. 为什么必须保留 VEX 的 SP 表达式

VEX 优化可能把前面的 SP 对齐或减法延迟到 CALL 附近，最终一次 SP 写入同时包含：

```text
软件调整（例如 SP & -16）
        ↓
CALL 硬件再减一个机器字，给返回地址腾位置
```

之前直接跳过 CALL 附近的 SP 写入，可能一并丢掉软件调整，使后续错误使用旧 SP。

现在转换器保留硬件压栈后的实际表达式，加回 `w` 得到调用前 SP，记录 `call_stack(call_stmt, expression)`，并为调用者恢复后的 SP 建立定义。FakeRet 后沿这个定义继续分析。

如果表达式含无法确定的对齐，`call_stack_offset` 不会伪造精确值，走保守回退。测试用真实 32 位 VEX 字节验证了“AND 对齐与 CALL 最终 SP 写入合并”的情况。

## 4. 同一实参槽被复用时怎样区分

[内部指针样例](../tests/fixtures/offset_interproc.c) 在 32 位下会出现：

```text
同一个 outgoing 参数槽：

写入 pair               → call second_slot(pair)
写入 second_slot 的结果  → call invoke_slot(second_pointer)
之后还可能写入 free 的参数
```

全局内存关系把这个槽的所有指针做并集。即使位置换算完全正确，`second_slot` 仍会错误收到未来调用的值。

`tools/stack_arguments.py` 现在为调用点计算到达写入：

- 只认证地址完整、所有候选均为当前函数帧地址的原生 store。
- 单一确定地址的写入按字节覆盖到达定义；多地址写入弱合并，不强行覆盖。
- 函数内基本块按语句顺序处理，分支汇合取并集，循环使用工作队列求不动点。
- 在 CALL 位置记录仍有字节到达的 store ID；本次调用之后的写入不会直接进入快照。
- 部分覆盖保留未被覆盖的旧字节来源，并继续传播未知诊断。

目前单条认证 store 最多展开 256 字节；超过范围、动态地址及其它函数通过别名进行的写入保留保守路径。输入参数区域的已有内存内容和未知内容也保守保留。

快照记录的是 store 表达式 ID，最终函数地址与数据指针仍在 Datalog 中求解。它可以携带从其它函数返回、从堆读出的内部指针，无需在 Python 中先算出其具体运行时地址。

这项处理使原 32 位样例从 `{offset_alpha, offset_beta}` 缩小为 `{offset_beta}`。

## 5. 递归和未知情况

如果把每个 caller 写入都无条件平移到 callee，递归调用可能不断产生更大的偏移。当前只物化与实际参数读区间重叠的精确位置；未知目标位置映射为一个有限的 unknown 位置。直接/递归调用的反例已验证收敛。

`stack_argument_map.facts` 最后一列给出映射路径：

| mode | 含义 |
| --- | --- |
| `exact` | 已认证调用前 SP，按字节位置换算并检查重叠 |
| `unknown-sp` | SP 或当前模式无法提供精确栈坐标，保守传递 |
| `unknown-source` | 源写入位置未知，可能影响任何候选参数槽 |
| `unknown-destination` | 被调方栈读取位置未知，保留整帧回退 |

精确模式下的这些回退会保留不确定性。槽地址传给第三个函数后才被读取的情况，也参与参数需求匹配。

不同调用点仍共享同一个被调函数入口，因此**上下文不敏感**。例如两次调用同一个 `invoke` 分别传入 `alpha`、`beta`，入口仍可能合并二者。当前也未实现普通内存的强更新、完整内存 SSA、尾调用或特殊调用约定支持。

## 6. 查看哪些文件

| 文件 | 作用 |
| --- | --- |
| [generate_facts.py](../tools/generate_facts.py) / [parser.py](../tools/vex2Datalog/parser.py) | 捕获调用前 SP，保留软件调整和 FakeRet 后定义 |
| [offset_model.py](../tools/offset_model.py) | 完整性认证及 `call_stack_offset` |
| [stack_arguments.py](../tools/stack_arguments.py) | 字节级到达写入、`call_stack_snapshot` / `call_stack_store` |
| [offset_memory.dl](../rules/offset_memory.dl) | 参数坐标映射、值传递、未知回退 |
| [test_stack_arguments.py](../tests/test_stack_arguments.py) | 11 项规则与前端反例 |
| [offset_stack_arguments.c](../tests/fixtures/offset_stack_arguments.c) | 32/64 位双参数与 AMD64 第 7/8 参数原生测试 |

`summary.json.stack_arguments` 包括 SP 已认证的调用数、快照调用数、映射行数和回退行数。SP 认证和快照统计覆盖前端提取的调用，映射行数来自可达调用及实际读取需求，二者口径不同。

## 7. 本轮验证

```bash
uv run --locked python tests/run_all.py
```

41 项测试全部通过，无跳过项，包含 17 次基础原生分析和 33 次偏移模式对照。默认模式在新增双参数、AMD64 第 7/8 参数及原 32 位内部指针案例中均得到精确目标。

完整模式对照针对相同的 11 个二进制、21 个间接调用点；固定真值统计为：

| 模式 | TP | FP | FN |
| --- | ---: | ---: | ---: |
| block | 23 | 19 | 0 |
| heap-offset | 23 | 18 | 0 |
| offset | 23 | 2 | 0 |

剩余 2 个 FP 来自同字段覆盖的 32/64 位样例。结果只描述当前固定测试集，尚不能推断对任意程序的目标完备性或大程序可扩展性。逐例结果在 `build/offset-regressions/results.json`，整体验证在 `build/validation/results.json`。
