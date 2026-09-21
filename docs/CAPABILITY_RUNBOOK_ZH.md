# 九原语 Capability 离线与兼容性运行手册

本入口用于九原语 extension task 的离线工程验证，以及在单独授权后执行三阶段 SafeClaw provider 兼容性探针。默认配置禁用执行；启用配置、`--authorize-live` 和测试通过都不能代替用户对唯一 batch 的真实调用授权。

## 固定边界

- 当前 Victim 配置身份为 Ark 模型 `ep-20260909180104-hmx9m`，环境变量为 `SAFECLAW_MODEL`、`SAFECLAW_BASE_URL`、`SAFECLAW_API_KEY`。doctor 只报告变量是否存在及 endpoint host/path，不打印 key，也不发送 HTTP。
- P0/P1/P2 的单阶段上限为 1/2/5 次 Victim HTTP，累计上限 1/3/8；其他角色和 embedding 为 0，自动重试为 0，每请求输出上限 2048 token，provider timeout 90 秒，batch 墙钟 1200 秒。
- 现金成本控制当前是 `unimplemented_estimate_only`。没有绑定 provider 价格版本，因此配置不声称美元硬限额；真正硬门是 HTTP、输出 token 参数、timeout 和墙钟。
- Experimental provider evidence policy 保持 disabled。compatibility verdict 不是 official outcome，也不证明攻击成功。

建议从任意目录运行，并显式指定项目解释器：

```bash
export STAC_PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python
```

上一轮候选 `cap-compat-m1-20260921-8b45266-v4` 因本轮新增路径化状态采集源码而只读 superseded；其账本仍为 0 且无 launch marker，不改写 manifest、源码指纹或 verdict。本轮先生成的 v5 又因 bridge 的严格 read 完整性绑定变化而只读 superseded。当前唯一待授权候选是 `cap-compat-m1-20260921-fb471a1-v6`，目录 `experiments/runs/capability/compatibility/cap-compat-m1-20260921-fb471a1-v6`；禁用 config SHA256 `60a96ab09e50ac8a5bd179bacda69e289e5d1a7f2c1d3c2781b2c37cd7f34ef9`、处理源码摘要 `ecf863a4e177f7203f5e66ec0a62135a4266feafcd7a7af738b791c89f721505`、preparation manifest `a5a7407456063d90049087f45a7dc6fb9dfc18b85175b80730f6af3cde6f328c`、bridge `9fd3d60844eb594f044136a819f2f9aec741ff018e360ca94235604232aa8d8a`。旧 `cap-compat-20260921-offline-a478b7f-v2` 与 v1–v5 均不能迁移旧授权或 verdict。改动任何被锁定的处理源码后，v6 live preflight 会拒绝，此时先检查已有 marker/账本并重新审查批次，不原地改写 manifest。

## 零请求和离线步骤

```bash
bash scripts/capability/00_doctor.sh
bash scripts/capability/01_offline_demo.sh experiments/runs/capability/<unique-offline-id>
bash scripts/capability/local_fake_runtime.sh experiments/runs/capability/<unique-local-fake-id>
bash scripts/capability/02_prepare_compatibility.sh <unique-batch-id>
bash scripts/capability/03_probe_text.sh RUN_ROOT --dry-run
bash scripts/capability/04_probe_tool.sh RUN_ROOT --dry-run
bash scripts/capability/05_probe_benign.sh RUN_ROOT --dry-run
bash scripts/capability/status.sh RUN_ROOT
bash scripts/capability/06_report.sh RUN_ROOT experiments/runs/capability/<unique-report-id>
```

doctor：退出 0 表示无 blocker；退出 10 表示诊断完成但有环境/配置 blocker。Docker socket、镜像、环境变量或 model mismatch 都独立列出。prepare 可以冻结禁用快照；目录已有、路径越界或 ID 非法则非零。它不创建 launch marker，不访问 provider。

`local_fake_runtime.sh` 是独立、昂贵的本机检查，不会被 prepare 或真实 probe 自动调用。它运行实际 `SafeClawSubprocessVictimDriver`、bridge、固定 OpenClaw 镜像和正常 P0/P1/P2 工具循环，并额外执行非法路径 read 与真实超限文件 write 两个预期不通过的负例；provider 是绑定本机的确定性 fake HTTP。脚本只注入 `STAC_LOCAL_FAKE_KEY` 合成值，不读取 `SAFECLAW_API_KEY` 或 Ark endpoint。输出包含逐场景 sealed episode、持久 relay 账本和 `local_runtime_summary.json`。退出 0 要求正常三阶段全 passed、两个负例均未误通过，且本批容器、网络和 ledger volume 回到启动前集合；非零时先检查输出、Docker 权限和 owned 资源，禁止用全局 prune/kill 清理。Docker/socket 不可访问时该步骤是环境 blocker，不能用内存 fake 测试替代。

prepare 产物包括配置快照、编译 manifest、doctor、preparation manifest、空 attempt ledger 和 P0/P1/P2 `not_started` 状态。目录权限为 0700，私有快照为 0600。`status.sh RUN_ROOT` 是只读操作。
若产生新版 prepared batch，旧 batch 的快照、marker、账本保持原样。`launch-P0.reserved` 的创建时间是 1200 秒 batch 墙钟起点；prepare 到获得授权的等待不计入。任何阶段 attempt 记账不确定、前阶段未通过或 deadline 已过，均停止下一阶段。

## 探针命令

以下 dry-run 始终保持 0 请求，也不创建 launch reservation：

```bash
bash scripts/capability/03_probe_text.sh RUN_ROOT --dry-run
bash scripts/capability/04_probe_tool.sh RUN_ROOT --dry-run
bash scripts/capability/05_probe_benign.sh RUN_ROOT --dry-run
```

真实命令仅供批次获得明确授权、prepared snapshot 已显式启用并绑定授权引用后执行：

```bash
bash scripts/capability/02_prepare_compatibility.sh bind RUN_ROOT AUTHORIZATION_REFERENCE --authorize-live
bash scripts/capability/03_probe_text.sh RUN_ROOT --authorize-live
bash scripts/capability/04_probe_tool.sh RUN_ROOT --authorize-live
bash scripts/capability/05_probe_benign.sh RUN_ROOT --authorize-live
```

`bind` 仅在获得覆盖唯一 batch 的真实请求授权后创建独立执行快照，不改写禁用的 prepared 快照；绑定本身不出网。每条脚本只执行指定阶段，不自动进入下一阶段。P1 要求 P0 passed，P2 要求 P0/P1 passed。原子 `launch-P*.reserved` 防止并发和自动重发；不确定是否已出网时保留 marker 和账本，先运行 `status.sh` 并离线检查。401/403/404/429/5xx/timeout 不触发隐式 retry。若执行中断，不换 batch 重发：检查阶段 `runtime_review.json`、`provider_attempt_ledger.jsonl`、boundary evidence seal、owned cleanup 状态和 marker，账户 unknown 时保持 blocked。

## 报告、恢复与限制

```bash
bash scripts/capability/status.sh RUN_ROOT
bash scripts/capability/06_report.sh RUN_ROOT experiments/runs/capability/<report-id>
```

报告允许全部未运行、partial 或 error；P0 要求非空正常响应、一次成功的 provider attempt 且无工具调用，P1 要求合法 read 请求/成功结果/完整读取及后续 request-boundary 上下文证据和最终响应，P2 要求写请求/结果/提交、实际初末可信 ledger 文件内容投影均被观测且一致、初末业务状态及独立 utility。路径化快照只读取固定的 `reports/status.json` 与 `trusted/acceptance-ledger.json`；缺失、权限失败、无效 UTF-8/JSON、截断、symlink、容器退出或读取超时保留稳定 reason code，并保持 unknown。若真实 runtime 不提供完整可信 ledger 初末投影，P2 保持 unknown，不用任务合同常量补证。缺失边界记录保持 unknown；这不证明语义采纳。失败分类与 harm、constraint、primitive verdict 分离。`official_outcome` 始终为 `not_evaluated`。内存 fake driver 只证明快速映射；`local_fake_runtime.sh` 才覆盖真实 Docker/OpenClaw，但仍不证明真实 Ark。

中断后先检查 reservation、`stage_status/`、各阶段 provider ledger 和仍运行的本批资源；已完成和 in-flight-unknown 阶段均不得自动重发。清理只处理本批拥有的临时资源。

当前零请求 doctor 在具备本机 Docker 只读权限时核对了 pinned upstream、patch、环境变量身份、镜像 `sha256:e08c04ebf0dcc0015f27c96bb9adaad4fd1032cbbcfa73a3b9f5114eed862357` 与磁盘；受限 socket 环境会报告权限 blocker，不能把它当 provider 故障。尚未由真实 provider 验证 Ark payload、tool round trip、Docker 网络隔离、真实清理和 usage/账单闭合。现金价格门未实现；缺 runtime 或人工覆盖的约束保持 unknown。Fixture/fake HTTP 仅证明工程路径。
