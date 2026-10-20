# 基础流程修复与验证记录

日期：2026-10-20。基于提交 `6f88d431f875afe515a3c39f1b24eb51666996b4`，修复保留在工作区，未提交或推送。

## 修复范围

主流水线迁移为统一的 facts schema v2；旧 facts 必须重新生成。修复不依赖原始 BPA 或官方 BPA-X 仓库的分析代码，仅复用本机已有 Python 依赖环境与 Soufflé。

- VEX 临时变量按基本块隔离；Load/Store/Call/Unop 使用统一的表达式 ID。
- 使用 VEX 语句顺序建立寄存器 reaching-def/def-use，修复先读后写和同机器指令多定义。
- 值分析使用定义版本，经 block ID 连接内存弱更新及别名读取。
- `IRSB.next` 提供目标表达式；即使 VEX 将寄存器目标常量折叠，也保留机器间接调用类型。
- 参数、返回寄存器、新调用目标与调用图在同一个 Datalog 最小不动点内联合传播；过程间边写出到文件。
- 栈偏移采用 entry-SP 基准累计；标量/仿射集合 widening 保证循环收敛。
- 基线采用每函数一帧、每全局 section 一块，避免数组内部地址被误分块；堆使用分配点抽象。
- 读取经 CLE 重定位的全局内存初值，修复全局静态函数指针种子遗漏；PLT 由 CLE 识别。
- 修正 AMD64 calloc/realloc 大小参数，保留 realloc 的可能内容；X86 分配大小当前为 unknown。
- 修复 DWARF 指针大小，评估采用明确的 entry-SP 基准、精确边界指标及单独 IoU。
- 运行入口统一 Python；重新生成输入 facts，记录输入 SHA256，文件锁隔离同目录并发；可选评估不覆盖源码目录中的 GT。
- 未解析调用和 unknown 分开输出；stripped 输入明确失败，无 DWARF 时跳过评估。

## 本次验证

环境：Python 3.12.3、GCC 13.3、angr/pyvex 9.2.173、pyelftools 0.31、Soufflé 2.5。

`tests/run_regressions.py`：7 个测试方法全部通过，其中原生编译/运行/分析案例 17 个；另覆盖定义流、偏移/内存、Unop/命名空间、传统 PLT、收敛/未知目标/stripped/无 DWARF。32 位运行在沙箱外完成。

| 案例 | 间接调用点 | TP | FP | FN |
|---|---:|---:|---:|---:|
| parameter_64 | 1 | 1 | 0 | 0 |
| parameter_32 | 1 | 1 | 0 | 0 |
| registers_64 | 2 | 2 | 0 | 0 |
| registers_32 | 2 | 2 | 0 | 0 |
| memory_64 | 4 | 4 | 2 | 0 |
| memory_32 | 4 | 4 | 2 | 0 |
| factory_64 | 2 | 2 | 2 | 0 |
| factory_32 | 2 | 2 | 2 | 0 |
| allocators_64 | 1 | 1 | 0 | 0 |
| allocators_32 | 1 | 1 | 0 | 0 |
| stack_parameter_64 | 1 | 1 | 0 | 0 |
| stack_parameter_32 | 1 | 1 | 0 | 0 |
| control_flow_64 | 1 | 2 | 0 | 0 |
| control_flow_32 | 1 | 2 | 0 | 0 |
| repository_demo_64 | 2 | 2 | 2 | 0 |
| repository_demo_32 | 2 | 2 | 2 | 0 |
| memory_64_pie | 4 | 4 | 2 | 0 |
| **合计** | **32** | **34** | **14** | **0** |

TP/FP/FN 统计的是每个调用点的目标边。分支案例的同一调用点可能有两个真实目标，因此边数与调用点数不同。oracle 来自这些小程序可审计的源代码；各程序也实际运行并通过返回值检查。本表仅描述本测试集。

基本参数与寄存器覆盖案例要求目标集合精确相等；内存、工厂和原仓库 demo 要求覆盖所有预期目标，并单独统计额外候选。当前保守内存抽象仍有 14 条额外边，不能解释为已解决精度问题。

## 本机直接运行已验证

```bash
cd /home/qc/Desktop/binwork/mywork/BPA
mkdir -p build
gcc -O0 -g -fno-pie -no-pie -fno-omit-frame-pointer pipeline/bin/test.c -o build/demo
./build/demo
./pipeline/run.sh build/demo --output build/demo-analysis --compare
```

仓库 demo 的两处间接调用均包含实际目标，输出各有 `{add, sub}`；`summary.json` 为 completed，unresolved_calls 为空。它们仍有额外候选与保守 unknown 提示，不能据此宣称对任意程序完备。

产物：

- `build/regressions.log`：完整测试结果。
- `build/regressions/results.json`：逐案例指标。
- `build/regressions/<case>/analysis/`：各案例 facts、分析摘要和可选 DWARF 评估。
- `build/demo-runtime.log`：本机原 demo 运行输出。
- `build/demo-analysis/`：文档运行命令的实际产物。

## 保留的限制

完全 stripped 函数恢复、字段/对象/调用上下文精化、完整 VEX/库副作用、外部回调、尾调用和间接跳转的联合恢复仍未实现。未知语义不会被包装成“没有目标”；诊断文件与 summary 保留可见提示。当前栈/全局块是保守基线，不能作为源级变量恢复精度的成果。

主分析依赖 CFGFast 生成的函数内 CFG 以及 ELF 函数符号。这里的闭环解决的是已提取函数上的调用目标/值流联合求解，不等于完全 stripped 二进制的端到端反汇编闭环。
