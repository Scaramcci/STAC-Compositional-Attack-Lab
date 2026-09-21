# Scripts

| 命令 | 用途与退出语义 |
|---|---|
| `bash scripts/capability/00_doctor.sh` | 九原语兼容性零 provider 诊断；只报告模型/endpoint 的非秘密身份及 blocker。 |
| `bash scripts/capability/01_offline_demo.sh OUTPUT` | 新目录中的 fixture compiler→runtime→oracle→report 闭环。 |
| `bash scripts/capability/02_prepare_compatibility.sh [RUN_ID]` | 冻结默认禁用的唯一 P0/P1/P2 batch，0 请求。 |
| `bash scripts/capability/02_prepare_compatibility.sh bind RUN_ROOT AUTHORIZATION_REFERENCE --authorize-live` | **仅在唯一 batch 的真实请求另获明确授权后**绑定独立执行快照；命令本身 0 请求，不修改禁用快照。 |
| `bash scripts/capability/03_probe_text.sh RUN_ROOT --dry-run` | P0 参数预演；`--authorize-live` 仍要求已启用快照和明确授权。 |
| `bash scripts/capability/04_probe_tool.sh RUN_ROOT --dry-run` | P1 参数预演；真实执行要求 P0 passed。 |
| `bash scripts/capability/05_probe_benign.sh RUN_ROOT --dry-run` | P2 参数预演；真实执行要求 P0/P1 passed。 |
| `bash scripts/capability/status.sh RUN_ROOT` / `06_report.sh RUN_ROOT OUTPUT` | 只读状态和 partial/error 报告；见 `docs/CAPABILITY_RUNBOOK_ZH.md`。 |
| `python -m stac_attack_lab.cli capability demo --config configs/capability/f1_status_acceptance.json --output experiments/runs/capability/<unique-id>` | 九原语 M0/M1 离线完整闭环；fake transport，零真实请求。 |
| `python -m stac_attack_lab.cli capability inventory/compile/validate/replay/report ...` | 九原语固定 upstream 核对、确定性编译、密封校验、只读重分析和报告。 |
| `bash scripts/run_cross_session_revalidation.sh prepare` | 创建唯一、默认禁用真实执行的复验目录，写入新 provenance/configuration review；不访问 provider。成功 0。 |
| `bash scripts/run_cross_session_revalidation.sh offline --run-root PATH --collection COLLECTION` | collection reanalysis：读取已有 collection，重新 normalize/mine/audit/admission；不叫 bridge replay。 |
| `bash scripts/run_cross_session_revalidation.sh offline --run-root PATH --bridge-responses RESPONSES.jsonl` | true bridge replay：要求 initialize/pre-state、每个 action/response/post-state 和 finish，经 live 共用 driver mapper 生成新 source events 后再 mine/audit/admission。缺字段或坏行返回 blocked，不猜 action。 |
| `bash scripts/run_cross_session_revalidation.sh live --run-root PATH --authorize-live` | 仅在单独授权后运行已经显式启用的 prepared run；原子 `launch.marker` 防止同一 run 重复/并发启动，随后即使 collection partial/error 也尽可能执行离线 mine/audit/admission。执行或离线阶段失败均返回非 0。 |
| `python -m stac_attack_lab.cli doctor --config ...` | 离线 workflow readiness；分开 config、implementation、environment、enabled 和 authorization。 |
| `python -m stac_attack_lab.cli benign prepare --config configs/benign_collection/live_pilot.disabled.json --run-id ID` | 创建正常 pilot 禁用快照；不访问 provider。 |
| `python -m stac_attack_lab.cli benign collect-live --config ... --run-id ID --authorize-live` | 正常 SafeClaw adapter；要求同一 prepared run、另行审核的 enabled runtime config 和调用授权。 |
| `bash scripts/run_safeclaw_sample_collection.sh` | legacy adversarial pilot/main collection（需单独授权）。 |
| `bash scripts/run_formal_evaluation.sh` | formal evaluation（需 frozen library 和单独授权）。 |
| `python -m stac_attack_lab.cli flow reanalyze ...` | 显式 Primitive v3 离线重分析；校验 collection seal/registry，写新 manifest、效果图、切片、分层准入和报告。 |
| `python -m stac_attack_lab.cli benign validate/prepare` | 校验正常场景并生成默认禁用快照；零网络请求。 |
| `python -m stac_attack_lab.cli benign collect-fixture` | 仅运行受版本控制的 synthetic 正常场景，经共用 collector/normalizer 进入 v3；拒绝 live-enabled 配置。 |

复验入口不复制历史 `experiments/runs`，不自动启用 live，不探测 provider，也不负责清理其他 run。prepare 会验证模板并写禁用配置、不可变 prepared snapshot、配置审核和 provenance；live 必须同时有仅改变 `execution_enabled` 的运行配置和 `--authorize-live`。launch reservation 在 collection 前原子创建，失败进程不能覆盖获胜进程的 live review/summary；可能已产生请求后的失败不会删除 marker。`max_tokens` 是 collection action 后累计的 Victim usage 检查，不是请求前硬 token 上限。

每次 offline 都写 `<RUN>/analyses/<mode-timestamp-id>/`，不覆盖旧分析。退出码：0 表示所需离线检查通过但 runtime review 仍可 pending；10 表示检查完成但门槛未满足；20 表示输入不足/blocked；30 表示配置或程序错误。live 的 2 表示执行和离线检查完成、等待 runtime review。查看 `<analysis>/offline_summary.json`、`offline_provenance.json`、`bridge_replay_diagnostics.json`、`provider_compatibility_report.json` 和 `provider_attempt_reconciliation.json`；历史输入只读引用，不得把派生报告写回历史 run。

`inputToolResultCallIds` 仍没有可信生产者并始终只作诊断。当前 relay/bridge 路径可生成 request-boundary context projection；版本化 policy 必须来自 runtime config，evidence 不能自授权。exact UTF-8 verifier 仅在显式 synthetic/experimental policy 下严格重算 arguments JSON、selector 和 projection，正式默认禁用。fake HTTP/replay 成功只证明工程链路，不证明真实模型、攻击或 official outcome。默认禁用准备命令为：

```bash
STAC_PYTHON=.venv/bin/python bash scripts/run_cross_session_revalidation.sh prepare \
  --template configs/sample_generation/cross_session_revalidation.disabled.json \
  --run-id <new-unique-run-id>
```

该命令仅生成 `execution_enabled=false` 配置，不是 live 授权。任何单条真实兼容性复验仍需单独审核 policy、provider payload 形状、预算和最终配置后再授权。

版本控制内的有界兼容性模板位于
`configs/sample_generation/provider_compatibility_revalidation.disabled.json`：
Attacker/Victim/Embedding 各最多 1 次、自动重试 0、墙钟 300 秒、provider evidence policy
保持 disabled。后续应先用它执行 `prepare --template ... --run-id <new-unique-id>`，再审查生成的
config/source hash；本轮不得执行 `live`。
