# 共同函数输入、AT 根策略与尾调用

2026-10-26。本轮落实 [BPA-X 对齐计划](BPAX_ALIGNMENT_PLAN.md) 的前三项基础工作。接口标记为 `control_schema=1`，沿用 facts schema v2 和 offset schema v2。

## 1. 共同函数清单与独立覆盖统计

### 导出与导入

每次前端生成都会写出：

```text
<output>/facts/functions.json
<output>/facts/instruction_inventory.json
<output>/coverage.json
<output>/function_coverage.json
```

`functions.json` 使用 ELF RVA，与 CLE 的加载地址分开；绑定当前 ELF 的 SHA256 和位宽。默认从函数符号提取，提供 `--functions` 后使用给定范围。

```bash
uv run --locked ./pipeline/run.sh ./program --output build/reference
uv run --locked ./pipeline/run.sh ./program \
  --functions build/reference/facts/functions.json \
  --roots main-and-at --output build/shared
```

同一输入应保持 SHA256 一致。改变符号表也会改变文件 SHA256；对 stripped 副本使用清单时，需要在独立确认代码和边界仍适用后显式创建绑定新文件的清单。默认仍拒绝无 `.symtab` 的输入；给定清单的 stripped 分析不等于自动函数恢复。

清单示意：

```json
{
  "schema": 1,
  "address_space": "elf-rva",
  "binary_sha256": "<ELF SHA256>",
  "bits": 64,
  "entry": "main",
  "functions": [
    {"name": "main", "start": 4352, "end": 4416, "source": "verified-boundaries"}
  ]
}
```

范围为左闭右开，要求位于可执行映射内，名称和入口唯一，函数之间不重叠；同地址符号通过 aliases 表示。SHA256、位宽、范围检查失败时停止，避免静默分析错误清单。

前端把所选入口交给 CFGFast，并按共同范围归属基本块。缺失的入口块和独立解码缺口均记录在结果中。共同范围只统一分析输入，不保证反汇编或边界本身正确。

### 使用 BPA-X 实际函数范围

```bash
uv run --locked python tools/function_manifest.py ./program \
  --from-bpax /path/to/bpa-x-test/build/facts/user_defined_addr_func.facts \
  --mapped-base 0x400000 --output build/bpax-functions.json

uv run --locked ./pipeline/run.sh ./program \
  --functions build/bpax-functions.json --roots main-and-at \
  --output build/shared-bpax-functions
```

`--mapped-base` 必须是该次 BPA-X/CLE 实际映射基址，示例值不适用于所有 ELF。输入 facts 应来自完全相同的 ELF。转换器过滤运行时辅助函数和不在可执行映射中的范围；导入的是函数清单，不是直接混用两套工具的传播 facts。

### 覆盖报告

`instruction_inventory.json` 在共同函数范围内独立解码 CALL/JUMP，分母不取自求解出的非空目标。

`coverage.json` 的普通间接 CALL 计数包括：

- `fixed_indirect_calls`：独立清单中的总数；
- `instruction_lifted`：对应机器指令是否进入提取的块；
- `frontend_extracted`：是否生成 call facts；
- `analyzed`：所属函数是否纳入值传播闭包；
- `reachable_from_main`：所属函数是否在从入口出发的已解析调用边闭包中；
- `nonempty`：是否有内部或外部候选目标。

每个调用点保留 `not-lifted`、`not-extracted`、`not-analyzed`、`unresolved`、`unknown`、`partial`、`resolved` 等状态。前端完成但求解未完成时，目标、分析范围和可达字段为 null。清单包含的函数不因此被称为真实可达；静态闭包中没有某函数，也不证明运行时不可达。

`summary.json` 还记录当前 `stage_running`，使被外层终止的任务可以定位停在哪个阶段。

## 2. AT 候选与两种根策略

```bash
# 默认：从 --entry 指定的入口分析，默认入口为 main
uv run --locked ./pipeline/run.sh ./program --roots main --output build/main

# 同时分析取过地址的用户函数及解析得到的调用闭包
uv run --locked ./pipeline/run.sh ./program --roots main-and-at --output build/main-at
```

AT（address-taken）证据来自指令中作为数据使用的函数地址常量，以及全局初始数据中的函数地址。普通直接 CALL/JUMP 的目标本身不作为取地址证据。PLT 地址另记为 external_address_taken，不作为需要 lift 函数体的用户根。

| 关系 | 含义 |
| --- | --- |
| `root` | 实际选定的分析入口 |
| `analysis_root` | main-and-at 策略增加的用户函数根 |
| `root_reason` | entry / address-taken 的来源 |
| `address_taken` | 用户函数、证据类型、证据机器地址 |
| `analyzed_func` | 入口及附加根经解析调用边扩展后的分析范围 |
| `reachable_func` | 仅从真实入口经解析调用边扩展的静态闭包 |

例如，一个未被 main 调用的函数地址出现在全局表中，main-and-at 会分析其函数体，但不会仅因此把它加入 reachable_func。测试中该函数内的回调能输出 alpha，同时 reachable_from_main 仍为 false。

## 3. 尾调用语义

### 识别与确认

- 直接 JMP 到另一已知函数或 PLT 入口，提取为尾调用。
- 间接非索引 JMP 先排除 CFGFast 已识别的跳转表和函数内跳转，保留为候选。
- 间接候选只有在完整性预分析认证跳转时 SP 恰好恢复为本函数入口 SP 后才升级为尾调用。
- 无法认证的候选保留 unconfirmed-tail / unsupported 信息，不生成已解析尾调用边。

这是当前 X86/AMD64 普通 ABI 下的受限推断。未知栈对齐、特殊调用约定、索引表形式的尾分发等仍可能无法确认，尚不覆盖所有间接 JMP。

### 参数坐标

设调用者入口 SP 为 S，转移前 SP 为 S+d，字长为 w，参数写入位置相对调用者入口为 x：

```text
普通 CALL：callee entry SP = S+d-w，参数位置换算为 x-d+w
尾 JMP：  callee entry SP = S+d，  参数位置换算为 x-d
```

尾调用没有额外压入返回地址，复用栈上已有返回地址。

若 f 直接尾跳到 g，自己没有读取栈参数，仅依靠 f 的 load facts 会漏掉参数需求。新增 argument_read 将 g 的需求沿尾调用链反向传回 f，再连接最初调用者的写入。SP 恢复到入口的精确转换保持绝对入口偏移不变；未知或非零 SP 情况采用有限的 unknown 需求，避免递归生成无界偏移。

### 返回值与返回续点

```text
caller 普通调用 f
f 尾调用 g
g 返回 → caller 原来调用 f 之后的位置
```

尾调用使用 function_return_value 中的结果代理连接返回寄存器值，代理不代表 JMP 之后的一条物理寄存器赋值。多个尾调用串联时，值传播仍在同一个不动点中推导。

return_continuation 沿尾调用链继承最初普通 CALL 的 FakeRet 后继。interproc_edge 为实际 Ret 建立继承返回边，尾跳转处不伪造返回指令。

### 输出范围

- `indirect_call_target.facts`：普通机器间接 CALL 的内部函数目标；
- `tail_call_target.facts`：直接/间接尾调用的内部函数目标；
- `external_call_target.facts`：外部目标，可用 coverage 中的 transfer 类型区分普通/尾调用；
- `unresolved_tail_call.facts`、`uncertain_tail_call.facts`：尾调用的独立诊断；
- `call_graph.facts`：两类调用均参与；
- `call_kind`、`tail_call`、`tail_candidate`、`tail_evidence`：提取与认证依据。

## 4. 验证与复现

```bash
uv run --locked python tests/test_alignment.py
uv run --locked python tests/run_all.py
```

本轮完整验证：49 项测试通过，无跳过；包含 17 次基础原生分析、33 次偏移模式对照和 13 次对齐功能分析。现有 offset 对照 TP/FP/FN 仍为 block=23/19/0、heap-offset=23/18/0、offset=23/2/0。

新测试覆盖：

- 32/64 位 AT 根扩展与 main 可达闭包隔离；
- 清单往返、SHA 错配、范围重叠、BPA-X TSV 转换；
- PIE RVA 清单，以及为 stripped ELF 提供已知边界；
- 32/64 位直接尾调用、间接尾调用、尾调用链、返回函数指针；
- AMD64 第 7/8 个栈参数经过不读取参数的尾转发函数；
- 普通 CALL 的返回续点沿尾调用链继承；
- SP 不恢复或不完整时不确认间接尾调用；
- computed goto / 跳转表不被当作尾调用；
- CALL 与尾 JMP 的一个字长坐标差异，32/64 位均有规则级检查。

记录在 `build/alignment-regressions/results.json` 和 `build/validation/results.json`。历史 SPEC 筛查报告使用改动前的源码快照，不自动成为当前版本的成绩。

真实 xz 64 位 O2 集成检查：成功导入本机 BPA-X 的 391 个用户函数范围，独立清单中的 60 个普通间接 CALL 均已 lift 并提取。main-and-at 完整分析在 180 秒、4 GiB 采样 RSS 保护预算下于最终求解阶段超时，未触发内存保护；该次与回归测试并行，不能用于性能速度比较。随后单独完成了共同输入、SSA、分块与尾调用认证阶段的检查，记录在 `build/alignment-large/`。这验证了接口接入，没有形成新版大型程序的最终目标或召回成绩。

后续仍需完整过程间 RD 等价验证、多对象分块、SIMD/宽写入、只读保护和大型求解性能。这三项基础能力完成不等于 BPA-X 全部功能已经对齐。
