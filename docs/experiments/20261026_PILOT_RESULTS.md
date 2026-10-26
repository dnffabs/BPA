# BPA-X 与本项目首轮实测

实验 ID：`20261026_pilot01`。本报告由原始记录生成。

## 小样例：完整人工真值与原生动态核验

| 分析组 | 完成次数 | TP | FP | FN | 预测边 |
| --- | ---: | ---: | ---: | ---: | ---: |
| bpa-x | 11 | 23 | 13 | 0 | 36 |
| block | 11 | 23 | 19 | 0 | 42 |
| heap-offset | 11 | 23 | 18 | 0 | 41 |
| offset | 11 | 23 | 2 | 0 | 25 |

11 个共同 ELF、21 个固定调用点、23 条真边；44 次分析。动态核验通过：11/11。

样例覆盖堆/栈/全局字段、内部指针跨函数返回并存储、32 位参数、AMD64 第 7/8 参数、循环、同字段覆盖。所有构建都使用相同 GCC flags，同一个 ELF 原样交给双方。

这些样例围绕本次偏移和参数扩展设计，只能验证这些机制；不代表真实程序的总体精度。`offset` 剩余 FP 来自同字段覆盖，普通内存仍然流不敏感。

## SPEC2017 首轮筛查

主配置为非 PIE、有符号的 GCC 13.3 O0/O2；保留正常优化行为。构建采用安装树自带 simple-build 命令的私有副本，未使用 runcpu 生成正式成绩。添加 `-fcommon -fno-pie -no-pie`；32 位 x264 显式链接系统已有的 `/lib/i386-linux-gnu/libm.so.6`。原安装树只读。

| ELF | test 校验 | 固定间接 CALL 点数 | BPA-X | block | heap-offset | offset |
| --- | --- | ---: | --- | --- | --- | --- |
| x264_r_32_O0 | completed | 496 | timeout / 180.2s | timeout / 180.0s | timeout / 180.1s | timeout / 180.2s |
| x264_r_32_O2 | completed | 549 | timeout / 180.1s | timeout / 180.2s | timeout / 180.1s | timeout / 180.1s |
| x264_r_64_O0 | completed | 496 | timeout / 180.0s | timeout / 180.1s | timeout / 180.0s | timeout / 180.1s |
| x264_r_64_O2 | completed | 538 | timeout / 180.1s | timeout / 180.2s | timeout / 180.2s | timeout / 180.2s |
| xz_r_32_O0 | completed | 64 | 3906 边 / 46 点 / 45.6s | timeout / 180.2s | timeout / 180.3s | timeout / 180.0s |
| xz_r_32_O2 | completed | 60 | 4618 边 / 51 点 / 49.7s | timeout / 180.3s | timeout / 180.3s | timeout / 180.0s |
| xz_r_64_O0 | completed | 64 | 5550 边 / 50 点 / 53.1s | timeout / 180.0s | timeout / 180.1s | timeout / 180.1s |
| xz_r_64_O2 | completed | 60 | 2585 边 / 43 点 / 66.5s | 1141 边 / 16 点 / 67.0s | 1141 边 / 16 点 / 88.7s | 78 边 / 8 点 / 36.3s |

表中“点”表示输出了主 ELF 用户函数目标的调用点。固定分母来自 ELF 函数符号范围内的独立 Capstone 反汇编，过滤规则相同；未覆盖/未解析点都保留。PLT/外部目标、尾调用不计入主边表。不能由候选数较少直接推断更准。

BPA-X 的预处理从 main 与全部 address-taken 函数出发保留函数；本项目采用 main 为根的调用图不动点。JSON 中记录了两者不同的 reachability_basis，不能把两者“可达函数”直接视为同一语义。固定调用点分母保持一致；动态执行证据用于确认真实可达性。

## 已确认的问题与后续优先级

1. **大型程序覆盖存在缺口。** xz 64 位 O2 的 28 条已观察真边中，BPA-X 覆盖 14 条，block/heap-offset 各覆盖 3 条，offset 覆盖 1 条。offset 的 78 条预测边和低 AICT 伴随漏边，不能解读为全面精度优势。
2. **SIMD/宽写入可复现丢指针。** [独立诊断](20261026_VECTOR_DIAGNOSTIC.md) 中，标量写入版双方保留 alpha；SIMD 写入版 BPA-X 漏 alpha，offset 仅输出错误 beta。真实 xz 的初始化也出现 movq→xmm、movhps、movups 序列，这是需要修复的已验证语义缺口，尚不能据此解释所有漏边。
3. **存在求解性能瓶颈。** 本项目的 21 个大型超时配置都已进入最终 analysis；BPA-X 的 4 个 x264 超时停在 global-mem-block.dl。180 秒只是一轮筛查上限，不能据此称永久无法完成。
4. **汇总指标会掩盖缺失的可达路径。** offset 在 xz 64 位 O2 的 summary 中 unresolved=0，但只有 8 个判为可达的间接调用点，且有 7 个 uncertain 标记；动态仍证明大量漏边。今后必须一起报告固定全集、前端覆盖、可达性、unknown 与动态漏边。
5. **普通同字段覆盖仍然产生误报。** 小样例中 offset 剩余两条 FP 属于此类，需要流敏感更新机制；它与 SIMD 漏边是不同问题。

## 资源和完成状态

每次静态分析固定 4 个 Soufflé 线程，180 秒筛查预算，0.2 秒采样进程组 RSS，达到 4 GiB 保护阈值后终止整个进程组。此保护会重复计算共享页，也会漏掉采样间隔中的尖峰，不是 cgroup 的硬内存上限。`memory_guard` 不等同于内核 OOM。

完整入口墙钟时间含前端、facts、SSA、分块和求解。GNU time RSS 是最大单进程峰值；采样进程组峰值另列。第一次试跑只做一次，不作为稳定速度比结论。

被外层终止时，工具自身 pipeline/summary.json 可能仍保留 running；本实验以外层 result.json / process.json 的 timeout 等最终状态为准。失败运行的 targets/reachable 记为 null，不把未导出的结果解释为空目标或不可达。

| 分析组 | 大型分析已执行 | completed | timeout | memory_guard | error/incomplete | 最大单进程 RSS MiB（有记录者） |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| bpa-x | 8 | 4 | 4 | 0 | 0 | 761.6 |
| block | 8 | 1 | 7 | 0 | 0 | 447.4 |
| heap-offset | 8 | 1 | 7 | 0 | 0 | 1338.5 |
| offset | 8 | 1 | 7 | 0 | 0 | 520.6 |

## 动态证据

- `x264_r_32_O0`：event_limit，10000 个已记录调用事件，12 条主 ELF 观察边；完整结束=False。负载：test-derived single-frame prefix; not the full 156-frame test workload。
- `x264_r_32_O2`：event_limit，10000 个已记录调用事件，13 条主 ELF 观察边；完整结束=False。负载：test-derived single-frame prefix; not the full 156-frame test workload。
- `x264_r_64_O0`：event_limit，10000 个已记录调用事件，12 条主 ELF 观察边；完整结束=False。负载：test-derived single-frame prefix; not the full 156-frame test workload。
- `x264_r_64_O2`：event_limit，10000 个已记录调用事件，13 条主 ELF 观察边；完整结束=False。负载：test-derived single-frame prefix; not the full 156-frame test workload。
- `xz_r_32_O0`：event_limit，10000 个已记录调用事件，29 条主 ELF 观察边；完整结束=False。负载：test: 1 MiB, compression level 0, one of the 12 test commands。
  - bpa-x：覆盖 29/29 条已观察边；漏边 0 条。
- `xz_r_32_O2`：event_limit，10000 个已记录调用事件，26 条主 ELF 观察边；完整结束=False。负载：test: 1 MiB, compression level 0, one of the 12 test commands。
  - bpa-x：覆盖 22/26 条已观察边；漏边 4 条。
- `xz_r_64_O0`：event_limit，10000 个已记录调用事件，29 条主 ELF 观察边；完整结束=False。负载：test: 1 MiB, compression level 0, one of the 12 test commands。
  - bpa-x：覆盖 29/29 条已观察边；漏边 0 条。
- `xz_r_64_O2`：event_limit，10000 个已记录调用事件，28 条主 ELF 观察边；完整结束=False。负载：test: 1 MiB, compression level 0, one of the 12 test commands。
  - bpa-x：覆盖 14/28 条已观察边；漏边 14 条。
  - block：覆盖 3/28 条已观察边；漏边 25 条。
  - heap-offset：覆盖 3/28 条已观察边；漏边 25 条。
  - offset：覆盖 1/28 条已观察边；漏边 27 条。

大型轨迹采用经过小样例核验的 GDB 断点＋单步方法，受事件数和时间预算限制。部分轨迹只能提供已观察边的证据；没有 test/train/ref 完整覆盖，不能据此宣称 soundness，静态预测但未观察到的边也不能直接算 FP。

## 追加诊断

- 将 xz 32 位 O2 的 offset 完整入口预算延长到 600 秒，结果仍为 **timeout**（600.238s，采样进程组峰值 972.5 MiB）。使用同一 SHA256 输入和全新 facts；这次追加结果与 180 秒主表分开保存。

- 对 xz 64 位 O2 的已生成输入 facts 单独启用 Soufflé profile。带 profile 的求解约 30.2 秒，最热的栈参数非认证写入回退规则累计约 14.9 秒（约 49% 的该次求解时段），生成约 1080 个计数元组。下一项 points_to_offset 的 flow 传播约 4.4 秒。这个 profile 有额外开销，且与追加长预算任务短时重叠，不能替代主表的正常运行时间。

  原始 profile 和逐规则汇总：[profile](/home/qc/Desktop/binwork/spec2017_bpa/results/20261026_pilot01/profiles/xz_r_64_O2_offset/profile.json)、[top_rules](/home/qc/Desktop/binwork/spec2017_bpa/results/20261026_pilot01/profiles/xz_r_64_O2_offset/top_rules.json)。正常输出 points_to_offset 有 730963 行；应优先检查栈参数回退的连接规模、重复候选组合与偏移传播规模。此处仅定位该配置的热点，未证明所有超时都由同一规则导致。

## 复现与原始记录

- [逐运行 CSV](/home/qc/Desktop/binwork/spec2017_bpa/results/20261026_pilot01/comparison.csv)：状态、时间、内存、固定分母、覆盖、候选边。
- [逐调用点差异](/home/qc/Desktop/binwork/spec2017_bpa/results/20261026_pilot01/site_differences.json)：BPA-X 与 offset 的增加/减少目标。
- [完整 JSON](/home/qc/Desktop/binwork/spec2017_bpa/results/20261026_pilot01/results.json)：全部运行及逐调用点状态。
- [环境和源码快照](/home/qc/Desktop/binwork/spec2017_bpa/results/20261026_pilot01/snapshot/environment.json)：HEAD、未提交修改、文件 SHA256、依赖、工具链。
- [实验入口](/home/qc/Desktop/binwork/spec2017_bpa/tools/run_pilot.py)；[动态采集脚本](/home/qc/Desktop/binwork/spec2017_bpa/tools/gdb_collect.py)。

```bash
cd /home/qc/Desktop/binwork/mywork/BPA
uv run --locked python /home/qc/Desktop/binwork/spec2017_bpa/tools/run_pilot.py micro --id 20261026_pilot01
uv run --locked python /home/qc/Desktop/binwork/spec2017_bpa/tools/run_pilot.py build --id 20261026_pilot01
uv run --locked python /home/qc/Desktop/binwork/spec2017_bpa/tools/run_pilot.py large --id 20261026_pilot01 --timeout 180
uv run --locked python /home/qc/Desktop/binwork/spec2017_bpa/tools/summarize_pilot.py --id 20261026_pilot01
```

同一 ID 下已记录的静态运行会跳过；需要重跑时使用新 ID，并先构建或复制对应输入。`analyze --case NAME --variant offset` 可只运行单个配置。构建日志、失败尝试、原生输出、facts 全部保存在 SPEC 实验工作区，未提交到 GitHub。

尚未完成：A0/A1 独立消融开关、其余 6 个 SPEC 源程序、正式长预算与三次重复、可扩展动态跟踪器及 test/train/ref 轨迹、PIE/stripped 鲁棒性。

版本：本项目 c4dd5b9 加本次已冻结的未提交改动；本机 BPA-X 0fb0a51。已对照快照核验两套工具的分析源码在实验期间没有变化。Python 分别为 3.12.15 / 3.12.3，angr 都为 9.2.173；完整环境见 snapshot。实验结果描述本机这两个版本，不等同于逐项复现论文原版。
