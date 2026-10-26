# SIMD 写入函数指针：最小复现

日期：2026-10-26。此实验用于定位优化后二进制中的漏边，没有修改两套工具的分析规则。

## 现象

同一段程序有两个语义等价的实现：标量版逐字段赋值；SIMD 版把两个指针放入 128 位向量后写回同一个结构体。两者都应调用 `offset_alpha`，返回结果均经过原生检查，且 GDB 已在实际 CALL 位置核验目标。

源码：[experiment_vector_callbacks.c](/home/qc/Desktop/binwork/mywork/BPA/tests/fixtures/experiment_vector_callbacks.c)。

```c
pair->first = first;          // first 的实际值是 offset_alpha
pair->second = offset_beta;
return pair->first() + 1;
```

SIMD 版用 `-DVECTOR_WRITES` 选择以下等价写入。这里是有意构造的向量操作诊断，不把它当成“仅开关编译器 SLP”的消融实验。

```c
typedef uintptr_t VectorPair __attribute__((vector_size(16)));
VectorPair values = { (uintptr_t)first, (uintptr_t)offset_beta };
__builtin_memcpy(pair, &values, sizeof(values));
```

## 实测结果

| 写入实现 | 工具 | 预测目标 | TP | FP | FN |
| --- | --- | --- | ---: | ---: | ---: |
| 标量 | BPA-X | alpha、beta | 1 | 1 | 0 |
| 标量 | 本项目 offset | alpha、beta | 1 | 1 | 0 |
| SIMD | BPA-X | 空 | 0 | 0 | 1 |
| SIMD | 本项目 offset | beta | 0 | 1 | 1 |

标量版也有一条误报，因此这里只能确认 SIMD 写入导致真实目标丢失，不能称标量版已经完全精确。每一行的工具都使用对应实现的同一个 ELF，分析前原生执行返回 0。

## 机器码与缺失语义

GCC 13.3 产生的关键序列为：

```asm
movq   %rsi, %xmm0          # 低 64 位装入 alpha
movhps (...), %xmm0         # 高 64 位装入 beta
movups %xmm0, (%rdi)        # 一次写入两个相邻字段
```

这不是源代码中的参数值发生变化。真实机器仍将 alpha 写入 first，beta 写入 second。分析器需要同时理解向量寄存器中的字节区间、合并操作与 16 字节写入后的字段位置。

本项目 facts 中出现 `64UtoV128`，以及 `initialize_callbacks` 的 `partial register write 128 bits` / `partial register write 64 bits`。目前标量 code_value/points_to 关系不足以表达两个指针分别占据向量的哪一半，导致 alpha 没有到达后续读操作；beta 被错误传播到 first 的读取。

真实 `xz_r_64_O2` 的 `lzma_stream_encoder_init` 也包含相同类型的 movq→xmm、movhps、movups 初始化序列。因此此诊断与真实程序相关；但没有逐条追踪所有漏边，不能宣称它是 xz 所有漏边的唯一原因。尾调用、未知操作、跨函数传播仍需单独排查。

## 复现与证据

编译公共选项：

```bash
gcc -m64 -O2 -g -fno-pie -no-pie -fno-ipa-cp -fno-ipa-sra \
  tests/fixtures/experiment_vector_callbacks.c -o vector_off
gcc -m64 -O2 -g -fno-pie -no-pie -fno-ipa-cp -fno-ipa-sra \
  -DVECTOR_WRITES tests/fixtures/experiment_vector_callbacks.c -o vector_on
```

两条命令在项目根目录使用，固定 noinline/noclone 和 IPA 选项是为了保留本次诊断函数与间接 CALL。该受控案例不是正常优化大型程序主表。

使用本机实验工具可完整生成两种实现的 ELF、原生校验、两工具分析和 GDB 轨迹：

```bash
uv run --locked python /home/qc/Desktop/binwork/spec2017_bpa/tools/run_pilot.py \
  diagnose-vector --id 20261026_vector_diagnostic
```

同一 ID 会复用已完成记录；独立重跑使用新的 ID。

- [原始诊断目录](/home/qc/Desktop/binwork/spec2017_bpa/results/20261026_vector_diagnostic)：两个 ELF、原生输出、facts、逐运行记录、GDB 轨迹。
- [主实验报告](20261026_PILOT_RESULTS.md)：8 个大型程序配置及 44 次基础小样例对照。

建议首先支持 `64UtoV128`、向量 lane 合并/提取、部分 XMM 更新以及宽 load/store 的分片指针传播；不能简单把整个 128 位向量看成一个函数地址，也不能靠丢弃 unknown 使目标数变小。
