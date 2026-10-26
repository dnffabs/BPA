# Facts schema v2 与 offset 扩展 v2

所有文件为 UTF-8 TSV，无表头。数值地址为 CLE 加载后的虚拟地址；ELF PIE 的符号、指令、全局数据和重定位指针使用同一 load bias。位宽以 bits 表示，内存访问宽度/块大小以 bytes 表示。Python 转换器见 `tools/vex2Datalog/parser.py`，Datalog 声明见 `rules/schema.dl`。

原始前端使用 schema v2；扩展 v2 增加调用点 SP 与栈写入快照，`summary.json` 记录 `offset_schema: 2` 和 `memory_model`。旧 facts 目录需重新执行流水线，生成新扩展所需输入。

## 身份

- `statement(stmt, function, bb, machine_address, position)`：position 是 VEX 语句在 IRSB 内的完整顺序。
- `temporary(eid, bb, tmp_number)`：临时变量的身份包含 bb。
- 表达式 EID、语句 ID、寄存器定义版本从同一分配器按不同 key 分配，互不混用。
- `register(location, name)`：位置以 VEX 架构寄存器偏移识别。部分寄存器访问标记 unknown，不能据此声称完整支持任意位操作。
- `entry_reg(function, location, version)`：每个函数独立的入口版本。

## 表达式与语句

| 关系 | 列 |
|---|---|
| constant | eid, bits, value（64 位值按有符号整数编码，32 位高地址保留正数） |
| copy | source_eid, destination_eid |
| binary | result_eid, operation, bits, left_eid, right_eid |
| unary | result_eid, operation, bits, source_eid |
| reg_read | stmt, function, bb, position, location, result_eid |
| reg_def | stmt, function, bb, position, location, source_eid, definition_version |
| load | stmt, function, machine_address, bytes, address_eid, result_eid |
| store | stmt, function, machine_address, bytes, address_eid, value_eid |
| call | stmt, caller_function, bb, machine_address, target_expression_eid, machine_is_indirect |
| call_stack | call_stmt, before_call_sp_expression_eid |

`IRSB.next` 通过同一个表达式转换器生成 `call.target_expression_eid`。机器调用类型根据反汇编的操作数判断，保留被 VEX 常量折叠的寄存器间接调用。

## 定义与跨函数流

`ssa.dl` 输出 `def_use(definition_version, read_expression)`。局部选择的是使用之前最近的定义；没有较早定义时使用入口到达定义，即使块内后面还有写入。分支汇合可有多个输入定义，不需要把指令地址伪装成表达式 ID。

每个调用记录 `call_input(stmt, register, snapshot_eid)`。在调用之后为 caller-saved 寄存器增加独立的虚拟返回/覆盖定义，callee-saved 寄存器沿 FakeRet 边保留原定义。

`call_stack` 单独记录硬件压入返回地址**之前**的 SP，不作为普通参数传递。VEX 可能将软件对齐/减法延迟到 CALL 的最终 SP 写入：转换器保留该表达式，加回一个机器字抵消硬件压栈，并为调用者 SP 建立恢复后的定义，供 FakeRet 后继续使用。不能直接删除整个最终 SP 写入，否则会丢失软件调整。

核心规则递归生成 `call_edge`，将参数 snapshot 连接到被调函数入口、返回寄存器连接到调用后的结果版本。由此得到的用户调用图和过程间边在同一次 Soufflé 最小不动点中更新。

## 内存与偏移

- `memory_model.py` 在 copy/def-use 上累计相对于函数入口 SP 的偏移，栈位移单独按操作位宽解释为有符号数，避免把 X86 `0xfffffffc` 当成约 4GB 的正偏移。
- 标量/仿射集合最多保留八个值，超过后 widening 为 unknown；未知栈对齐不猜测精确偏移。
- `offset_model.py` 认证值集合的完整性；必须覆盖所有生产规则及其输入组合，才能抑制通用指针传播。只得到部分值、load、调用输出、未知输入和未证明的循环不能被认证。
- 最终求解使用带位置的关系；原 `points_to`、`memory_code`、`memory_pointer` 仅是删除偏移后的兼容投影。它们可用于查看块身份，不能反向参与普通 load/store 匹配。
- store 对所有候选位置做流不敏感弱更新；load 根据块和字节区间是否重叠读取候选。未知位置读匹配块内所有写，未知位置写匹配该块所有读；精确写不会因生成块级投影而污染其它字段。
- 全局初始值来自 CLE 已应用重定位后的内存；按机器字对齐扫描，未声称覆盖 packed/非对齐初始化指针。

`stack_boundary/stack_aloc` 的 offset 是 entry-SP 基准；DWARF 评估同样转换到这一基准。尚不支持的 DWARF 位置会被统计为 skipped，不猜测任意优化后帧基准。

### 偏移扩展的输入

| 关系 | 列与含义 |
| --- | --- |
| `memory_model` | mode：`block`、`heap-offset` 或 `offset` |
| `complete_value` | eid：通过预分析完整性认证的表达式 |
| `offset_literal` | eid, signed_displacement：已认证的字面常量位移 |
| `affine_stack` | eid, function, entry_sp_offset：预分析得到的可能栈偏移，仅已认证的表达式可精确播种 |
| `call_stack_offset` | call_stmt, entry_sp_offset：认证的调用前 SP 偏移，可能有多个完整备选 |
| `certified_stack_store` | store_stmt, entry_sp_offset：地址完整且全部属于当前函数帧的原生写入位置 |
| `call_stack_snapshot` | call_stmt：已根据语句顺序及函数内 CFG 生成栈写入快照的调用点 |
| `call_stack_store` | call_stmt, store_stmt：仍有字节可能到达该调用的已认证写入 |

完整性认证不会凭空完善预分析；它让不完整结果继续走保守传播。跨函数传入的整数位移暂不作为动态 0-base 精确位移，未识别为字面常量时降级。

### 偏移扩展的输出

| 关系 | 列 |
| --- | --- |
| `points_to_offset` | eid, block, kind, offset |
| `memory_code_offset` | block, kind, offset, size_bytes, code_address |
| `memory_pointer_offset` | block, kind, offset, size_bytes, target_block, target_kind, target_offset |
| `memory_unknown_offset` | block, kind, offset, size_bytes |
| `stack_argument_map` | call_stmt, source_block, source_kind, source_offset, source_size, dest_block, dest_kind, dest_offset, dest_size, mode |

`kind` / `target_kind` 为 `exact` 或 `unknown`。`exact, 8` 表示精确字节偏移 8；`unknown, 0` 中的 0 只是规范化占位，表示块内任何位置，不能当成精确偏移 0。负数是合法偏移，不用 `-1` 表示未知。

`points_to_offset` 和 memory 关系中的精确偏移均相对于**块起点**。若 `stack_aloc(stk_f,f,-32,40)` 且某表达式相对于 entry-SP 的偏移为 `-24`，它在 `stk_f` 中的偏移为 `-24 - (-32) = 8`。不要将这两个坐标系直接混用；观测跨度也不用于排除未知位置。

动态 0-base 运算从 `H[0] + 8` 得到 `H[8]`，从 `H[8] + 8` 得到 `H[unknown]`，复制或直接解引用保留已有偏移。零位移保留已有位置。已认证的栈仿射计算和绝对全局地址由预分析直接提供精确位置，不受上述动态重复位移规则限制。

部分字节覆盖、宽度不匹配或偏移未知时可能无法完整重建指针：规则保留已知候选，并将未知语义传播到 `uncertain_call`。内存采用弱更新，精确偏移不意味着写入顺序敏感。

### 栈参数与内存函数摘要

寄存器实参、返回值和内存中保存的数据指针传递完整的 `block,kind,offset`。默认 `offset` 模式对认证 SP 做坐标换算：若调用前 SP 为调用者 entry-SP 的 `d`，某写入为 `x`，则其被调者 entry-SP 偏移为 `x-d+word_size`。换成块内坐标时再加调用者块起点、减被调者块起点。

映射保留源写入宽度，并只物化与实际参数读取区间重叠的位置，避免递归调用产生无限位移。槽地址逃逸到其它函数后的读取也参与需求匹配。`stack_argument_map.mode` 为 `exact`、`unknown-source`、`unknown-sp` 或 `unknown-destination`。

已认证的本地栈写入使用 `call_stack_store` 选取调用点的到达值：单一确定地址的写入按字节覆盖旧定义，模糊地址只做弱合并，分支路径取并集。动态/外来别名、输入参数区域和未知内存内容保守保留。这只细化栈传参，不改变普通堆/全局内存的流不敏感模型；不同调用点仍共享被调函数入口。

未知 SP、未认证写入或未知目标位置保留回退，相关未知性可传播到 `uncertain_call`。详细推导及复用槽例子见 [STACK_ARGUMENTS.md](STACK_ARGUMENTS.md)。

`memcpy` / `memmove` / `strcpy` / `realloc` 复制摘要把目的存储位置退化为 `unknown`，但保留所复制指针的目标偏移，并传播内存未知内容；复制长度、目的位移平移、`realloc` 保留前缀尚未精确建模。
