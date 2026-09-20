# Pilot 诊断与正常入口实现

当前实现把离线诊断、执行开关和调用授权分开。`doctor` 可以检查禁用配置；它不会启动容器或访问模型 endpoint。`collect-live` 仍同时要求配置中的 `execution_enabled=true` 和命令行 `--authorize-live`，版本控制模板保持禁用。

## 入口

```bash
# fixture：纯离线
python -m stac_attack_lab.cli doctor \
  --config configs/benign_collection/synthetic_stage_a.disabled.json

# 正常 SafeClaw pilot：只做离线/本机环境诊断
python -m stac_attack_lab.cli doctor \
  --workflow-kind benign_collection \
  --config configs/benign_collection/live_pilot.disabled.json

# 只生成禁用准备快照，不请求 provider
python -m stac_attack_lab.cli benign prepare \
  --config configs/benign_collection/live_pilot.disabled.json \
  --run-id <unique-run-id>
```

真实入口是以下命令，但禁用模板会拒绝；本轮没有执行：

```bash
python -m stac_attack_lab.cli benign collect-live \
  --config <reviewed-enabled-runtime-config.json> \
  --run-id <same-prepared-run-id> \
  --authorize-live
```

## 状态与语义

- `config_valid`、`implementation_ready`、`environment_ready`、`execution_enabled` 和 `authorization_state` 独立报告。禁用不等于配置或环境损坏。
- compatibility probe 只判定预注册的一次请求/响应协议观测，不要求 accepted sample 或跨会话证据，也不会自动追加请求。
- 旧 run 汇总只读；执行完成且 admission 失败报告为 `execution_complete_admission_failed`，不会重写旧产物。
- live preflight 在拒绝启动前保存完整 `sample_collection_preflight.json`。外部命令的缺失、权限、超时、daemon 不可达和 image 缺失有独立 reason code。
- shell 入口支持项目内或绝对配置路径、YAML/JSON 和外部 cwd；`.`/`..` 与路径型 run ID 被拒绝。`--print-output-dir` 不创建 run 目录。dotenv 由 Python 作为数据解析，不由 shell `source` 执行。

## 正常 pilot adapter

`SafeClawBenignInteractionAdapter` 将受版本控制的正常场景和合作策略映射到现有 `SafeClawSubprocessVictimDriver`。因此 bridge、provider relay、请求账本、边界证据、墙钟和有界收尾仍走同一生产合同；新入口没有 construction attacker 或官方安全 evaluator。

禁用模板使用单会话、最多两次目标请求（一次工具调用及其后续回复所需的最小闭环）、一次 embedding 上限、零自动重试和 300 秒墙钟。合作策略本身是确定性的，不发出模型请求。正常完成只决定 collection execution status；v3 observation、planning-reference 资格、跨会话能力、runtime review、授权和 official outcome 分开。单会话样本不要求跨会话门；声明跨会话的场景仍需严格 read-from 证据。

模板中的正常 runtime task 是从历史开发任务结构审查后形成的独立无敏感内容模板。SHA256 只绑定具体文件，不能证明审查者身份或生产真实性。真实 provider payload、网络隔离、容器清理和账本闭合仍需一次另行授权的有界兼容性验证。

## 离线验证

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q \
  tests/unit/test_workflow_readiness.py \
  tests/unit/test_benign_collection.py \
  tests/unit/test_adversarial_collection_runtime.py \
  tests/unit/test_cross_session_revalidation.py
make check PYTHON=python
make schemas PYTHON=python
git diff --check
```

fake driver 集成覆盖 reviewed message → production driver contract → collector 落盘 → v3 reanalysis；provider relay 的本地 fake HTTP 回归继续覆盖真实 relay/parser。两者属于工程兼容性证据，不是实际 provider 成功或 official outcome。
