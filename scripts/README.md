# Scripts

| 命令 | 用途与退出语义 |
|---|---|
| `bash scripts/capability/00_doctor.sh` | 九原语兼容性零 provider 诊断；只报告模型/endpoint 的非秘密身份及 blocker。 |
| `bash scripts/capability/01_offline_demo.sh OUTPUT` | 新目录中的 fixture compiler→runtime→oracle→report 闭环。 |
| `bash scripts/capability/local_fake_runtime.sh OUTPUT [--scenario P0|P1|P2|P1_REJECTED|P2_INCOMPLETE]...` | 真实 SafeClaw/OpenClaw 容器与本机 fake provider 的显式 M1 检查；可用新目录顺序单测场景，不读取真实 provider 凭证，需本机 Docker/socket。 |
| `bash scripts/capability/02_prepare_compatibility.sh [RUN_ID]` | 冻结默认禁用的唯一 P0/P1/P2 batch，0 请求。 |
| `bash scripts/capability/02_prepare_compatibility.sh bind RUN_ROOT "$STAC_APPROVAL_REF" --authorize-live` | **仅在唯一 batch 的真实请求另获明确授权后**输入实际审计引用并绑定独立执行快照；字面占位符会被拒绝，命令本身 0 请求，不修改禁用快照。 |
| `bash scripts/capability/03_probe_text.sh RUN_ROOT --dry-run` | P0 参数预演；`--authorize-live` 仍要求已启用快照和明确授权。 |
| `bash scripts/capability/04_probe_tool.sh RUN_ROOT --dry-run` | P1 参数预演；真实执行要求 P0 passed。 |
| `bash scripts/capability/05_probe_benign.sh RUN_ROOT --dry-run` | P2 参数预演；真实执行要求 P0/P1 passed。 |
| `bash scripts/capability/status.sh RUN_ROOT` / `06_report.sh RUN_ROOT OUTPUT` | 只读状态和 partial/error 报告；见 `docs/CAPABILITY_RUNBOOK_ZH.md`。 |
| `07_m2_prepare.sh OUTPUT` | 以禁用模板生成 M2 F1 八单元 materialized SafeClaw tasks、guard policy 和不可变 manifest；0 请求。 |
| `08_m2_offline_check.sh RUN_ROOT REPORT_ROOT` | 重验输入/hash/配对并生成完整分母报告和盲化人工审核表；0 请求。 |
| `09_m2_fake_http.sh OUTPUT` | 本机 loopback fake provider 验证生产 relay 的 G-bind 阻断与 sham 放行；无真实 provider，需 socket。 |
| `10_m2_live_unit.sh bind|run ...` | **待唯一 M2 batch 另获明确授权后**绑定实际审计引用并逐单元执行；不会继承 M1 授权/额度，禁止放入本机一键测试。 |
| `11_m2_local_runtime.sh OUTPUT [--unit UNIT_ID]...` | 实际 OpenClaw/production driver + 本机 deterministic fake provider 的 M2 闭环；单元或八项矩阵均写 seal、ledger、cleanup、完整分母报告，拒绝公网 provider 地址且不读取真实凭证。 |
| `12_m2_ai_review.sh prepare|validate|dry-run|bind|run|resume|status|report|import|merge ...` | M2 去标识 case 的独立 AI 审核入口。`prepare RUN_ROOT [CONFIG]` 支持全量或显式子集；宿主封存 pointer allowlist，响应在语义校验前受控留证。当前两项模板上限 2 次 Annotation HTTP、逐 case 独立上下文、零重试、无工具；`merge` 显式保留跨 prompt 来源，AI 标签与独立人工审核分开统计。`prepare/validate/dry-run/merge` 为零请求，`bind/run` 必须另获覆盖该唯一审核批次的明确授权。 |
| `13_m3_f3.sh prepare|validate|status|report|review-export|bind|run ...` | M3-A F3 三条件双会话入口。零请求模式生成或验证分母、分层报告和空白 Adopt 包；run 复用生产 driver，S1 Victim write 通过后才新建 actual session，并验证版本化 S2 read-from。非 benign 单元要求同 batch benign 的封存结构链和 cleanup 已通过。bind/run 需覆盖唯一 batch 的新授权。 |
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
| `bash scripts/capability/14_m3_f3_ai_review.sh prepare|validate|dry-run|status|bind|run|report|import ...` | F3 双判断 AI 审核，复用 M2 有界执行器；新批次默认禁用、3 个 case 各一次请求，独立授权后才可 bind/run。 |
| `bash scripts/capability/15_m3_f5.sh prepare|validate|status|bind|run|report ...` | F5 正常任务与外部 benign 引用；`prepare OUTPUT --config configs/capability/m3b_f5_external.disabled.json` 生成仅 direct/semantic 的禁用新批，validate/status/report 只读复算历史封存证据，bind/run 需新批明确授权。 |
| `PYTHONPATH=src python scripts/capability/run_f5_external_local_fake_runtime.py <unique-output>` | 本机 fake provider 经外部 v11 引用、synthetic binding、真实 OpenClaw/bridge/relay、两单元事件落盘与比较报告；无真实模型请求，需本机 Docker/socket。 |
| `PYTHONPATH=src python scripts/capability/run_f5_local_fake_runtime.py <unique-output>` | 本机 fake provider 经真实 OpenClaw/bridge/relay 验收 F5 三案例；只落盘合成证据，不发真实模型请求。 |
| `PYTHONPATH=src python scripts/capability/revalidate_f5_local_fake_runtime.py <sealed-run> <unique-output>` | 对封存的 F5 本机集成产物用当前原样 verifier 只读重算，校验 bundle 与输入 hash，并生成新派生验收报告。 |

上述 capability 脚本使用当前环境的 `python`（或显式 `STAC_PYTHON`）。从 `(base)` 终端调用时，使用 `conda run -n stac bash scripts/capability/<脚本> ...`；不要在未设置对应批次授权引用时执行 `bind`/`run`。长输出路径应作为单个 shell 参数传入，避免终端换行拆成第二条命令。

M2 最终本机矩阵 `m2-local-acceptance-20260922-b6da0cd-v3-final` 已通过；查收摘要位于相邻 `m2-final-local-review-20260922-b6da0cd-v1/acceptance_review.json`。唯一新的 `m2-f1-candidate-20260922-b6da0cd-final-v1` 仍为 disabled 且无 execution binding；不要对这些已存在目录重跑 07/08/11，真实 M2 不由本机验收自动授权。完整路径及后续步骤见 [Capability 运行手册](../docs/CAPABILITY_RUNBOOK_ZH.md)。

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
# F5 prospective repeat preparation: `bash scripts/capability/16_m3_f5_repeats.sh prepare <new-plan-root>` compiles three disabled F5 batches; `validate`, `status <plan-root> <r01|r02|r03>` and `report <plan-root> <new-report.json>` perform no provider requests. `bash scripts/capability/17_stage_summary.sh <new-output.json>` regenerates the F1/F3/F5 sealed-source summary. See `docs/CAPABILITY_RUNBOOK_ZH.md` for the authorized per-group bind/run boundary.
