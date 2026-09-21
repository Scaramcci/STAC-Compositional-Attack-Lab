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

## 零请求和离线步骤

```bash
bash /path/to/repo/scripts/capability/00_doctor.sh
bash /path/to/repo/scripts/capability/01_offline_demo.sh \
  experiments/runs/capability/<unique-offline-id>
bash /path/to/repo/scripts/capability/02_prepare_compatibility.sh <unique-batch-id>
```

doctor：退出 0 表示无 blocker；退出 10 表示诊断完成但有环境/配置 blocker。Docker socket、镜像、环境变量或 model mismatch 都独立列出。prepare 可以冻结禁用快照；目录已有、路径越界或 ID 非法则非零。它不创建 launch marker，不访问 provider。

prepare 产物包括配置快照、编译 manifest、doctor、preparation manifest、空 attempt ledger 和 P0/P1/P2 `not_started` 状态。目录权限为 0700，私有快照为 0600。`status.sh RUN_ROOT` 是只读操作。

## 探针命令

以下 dry-run 始终保持 0 请求，也不创建 launch reservation：

```bash
bash scripts/capability/03_probe_text.sh RUN_ROOT --dry-run
bash scripts/capability/04_probe_tool.sh RUN_ROOT --dry-run
bash scripts/capability/05_probe_benign.sh RUN_ROOT --dry-run
```

真实命令仅供批次获得明确授权、prepared snapshot 已显式启用并绑定授权引用后执行：

```bash
bash scripts/capability/03_probe_text.sh RUN_ROOT --authorize-live
bash scripts/capability/04_probe_tool.sh RUN_ROOT --authorize-live
bash scripts/capability/05_probe_benign.sh RUN_ROOT --authorize-live
```

每条脚本只执行指定阶段，不自动进入下一阶段。P1 要求 P0 passed，P2 要求 P0/P1 passed。原子 `launch-P*.reserved` 防止并发和自动重发；不确定是否已出网时保留 marker 和账本，先运行 `status.sh` 并离线检查。401/403/404/429/5xx/timeout 不触发隐式 retry。

## 报告、恢复与限制

```bash
bash scripts/capability/status.sh RUN_ROOT
bash scripts/capability/06_report.sh RUN_ROOT experiments/runs/capability/<report-id>
```

报告允许全部未运行、partial 或 error；P0 只判断正常响应可解析，P1 判断合法 read round trip，P2 判断 `reports/status.json` 的独立业务 utility。失败分类与 harm、constraint、primitive verdict 分离。`official_outcome` 始终为 `not_evaluated`。

中断后先检查 reservation、`stage_status/`、各阶段 provider ledger 和仍运行的本批资源；已完成和 in-flight-unknown 阶段均不得自动重发。清理只处理本批拥有的临时资源。

当前尚未由真实 provider 验证 Ark payload、tool round trip、Docker 网络隔离、真实清理和 usage/账单闭合。现金价格门未实现；缺 runtime 或人工覆盖的约束保持 unknown。Fixture/fake HTTP 仅证明工程路径。
