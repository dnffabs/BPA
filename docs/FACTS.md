# Facts schema v2

所有文件为 UTF-8 TSV，无表头。数值地址为 CLE 加载后的虚拟地址；ELF PIE 的符号、指令、全局数据和重定位指针使用同一 load bias。位宽以 bits 表示，内存访问宽度/块大小以 bytes 表示。Python 转换器见 `tools/vex2Datalog/parser.py`，Datalog 声明见 `rules/schema.dl`。

## 身份

- `statement(stmt, function, bb, machine_address, position)`：position 是 VEX 语句在 IRSB 内的完整顺序。
- `temporary(eid, bb, tmp_number)`：临时变量的身份包含 bb。
- 表达式 EID、语句 ID、寄存器定义版本从同一分配器按不同 key 分配，互不混用。
- `register(location, name)`：位置以 VEX 架构寄存器偏移识别。部分寄存器访问标记 unknown，不能据此声称完整支持任意位操作。
- `entry_reg(function, location, version)`：每个函数独立的入口版本。

## 表达式与语句

| 关系 | 列 |
|---|---|
| constant | eid, bits, signed64_value |
| copy | source_eid, destination_eid |
| binary | result_eid, operation, bits, left_eid, right_eid |
| unary | result_eid, operation, bits, source_eid |
| reg_read | stmt, function, bb, position, location, result_eid |
| reg_def | stmt, function, bb, position, location, source_eid, definition_version |
| load | stmt, function, machine_address, bytes, address_eid, result_eid |
| store | stmt, function, machine_address, bytes, address_eid, value_eid |
| call | stmt, caller_function, bb, machine_address, target_expression_eid, machine_is_indirect |

`IRSB.next` 通过同一个表达式转换器生成 `call.target_expression_eid`。机器调用类型根据反汇编的操作数判断，保留被 VEX 常量折叠的寄存器间接调用。

## 定义与跨函数流

`ssa.dl` 输出 `def_use(definition_version, read_expression)`。局部选择的是使用之前最近的定义；没有较早定义时使用入口到达定义，即使块内后面还有写入。分支汇合可有多个输入定义，不需要把指令地址伪装成表达式 ID。

每个调用记录 `call_input(stmt, register, snapshot_eid)`。在调用之后为 caller-saved 寄存器增加独立的虚拟返回/覆盖定义，callee-saved 寄存器沿 FakeRet 边保留原定义。CALL 的硬件压入返回地址不作为调用者帧的持久 SP 变化。

核心规则递归生成 `call_edge`，将参数 snapshot 连接到被调函数入口、返回寄存器连接到调用后的结果版本。由此得到的用户调用图和过程间边在同一次 Soufflé 最小不动点中更新。

## 内存与偏移

- `memory_model.py` 在 copy/def-use 上累计栈偏移，参考点为函数入口 SP。
- 标量/仿射集合最多保留八个值，超过后 widening 为 unknown，确保循环可收敛。
- 这一预分析只生成种子和块；最终 code/points-to/memory 集合在 Datalog 中求解。
- `points_to(eid, block_id)`、`memory_code(block_id, function_address)`、`memory_pointer(block_id, other_block_id)` 分别表示表达式指向的块、块内函数地址、块内指针。
- store 对所有可能指向的块做弱更新；load 从所有候选块取值。不会要求地址 EID 相同或刚好等于边界。
- 全局初始值来自 CLE 已应用重定位后的内存；按机器字对齐扫描，未声称覆盖 packed/非对齐初始化指针。

`stack_boundary/stack_aloc` 的 offset 是 entry-SP 基准；DWARF 评估同样转换到这一基准。尚不支持的 DWARF 位置会被统计为 skipped，不猜测任意优化后帧基准。
