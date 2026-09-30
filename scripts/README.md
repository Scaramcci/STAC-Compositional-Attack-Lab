# 当前脚本

`attack_program/` 是唯一的工作流脚本目录。所有输出目录必须尚不存在。薄包装脚本将参数原样传给 `python -m stac_attack_lab.attack_program.cli`；用 `--help` 查看具体子命令参数。CLI 成功返回 0；argparse 参数错误、已捕获的门槛和路径错误返回 2；`r4-local-fake` 有未完成案时也返回 2。其他异常为非零退出，需查看 traceback。

- `00_doctor.sh`：离线 pinned task/judge 检查。
- `01_catalog.sh`、`02_split.sh`：任务目录与组级 split。
- `03_develop.sh`、`04_library.sh`：离线开发样本与 synthetic 库。
- `08_results.sh`：状态与 replay/audit 包装入口。
- `10_demo_r2.sh`：R2 全尝试 synthetic 工程闭环。
- `11_demo_r3.sh`：R2 库、三臂多样本 Planner 与独立 replay/audit 总演示。
- `12_r4_runtime_fake.sh`：单次 R4 本机 fake runtime 入口；使用真实容器、relay、工具和状态采集。
- `13_r4_prepare.sh`：准备默认禁用的 R4 真实开发候选；仅在 fake 通过后使用。
- `14_r4_control.sh`：R4 doctor、validate、status、authorization-preview、bind、run-batch、review、replay 包装入口。真实 bind/run 需用户批准的该批原文记录、文件 SHA256 与 `--acknowledge-real-authorization`；缺任一项默认零请求拒绝。凭证只从 `SAFECLAW_API_KEY` 环境读取。
- `15_r4_fake_check.sh`：三案通过新版 prepare→fake binding→activate/run→terminal 的 Docker/local-fake 总验收，保存退出码并运行独立 replay/audit；需本机 Docker、pinned OpenClaw 镜像与隔离网络。fake 不读取项目 provider 凭证，只用固定 loopback endpoint 和 fake key。
- `16_r4_generation_fake_check.sh`：有界 Attacker generation（3 slots/最多 3 次 loopback HTTP）→严格候选封存→独立 Victim disabled prepare→fake bind/run→replay/audit；检查全尝试分母、known usage 和 `memory/YYYY-MM-DD.md` committed write。真实 generation 默认禁用。
- `17_r4_generation_real_victim.sh`：按授权顺序对已封存的三个真实生成候选执行逐案 validate→bind→run，保存授权 SHA、退出码、status 和 terminal；只安全解析白名单 `SAFECLAW_API_KEY`，不重试，terminal/账本异常即停止后续 slot。需用户明确 B 阶段授权和真实凭证环境。
- `18_r4_real_diagnosis.py`：对已关闭真实生成 Victim 批次做只读证据诊断；输出必须是全新目录，不改写历史 raw、ledger、manifest 或分母。

有界生成的只读状态与真实 A 授权预览通过 `14_r4_control.sh r4-generation-status --generation <目录>` 和 `14_r4_control.sh r4-generation-authorization-preview --plan <含明确 Attacker 身份的计划> --prompt configs/attack_program/r4_attacker_prompt_v1.txt` 查看。预览记录不是授权；真实 A 要另存用户批准的 JSON 原文、SHA256 与显式旗标。B 阶段有效候选由 `r4-generation-prepare-victim --generation <A 目录> --output <新目录>` 独立准备；逐候选 `r4-validate`、`r4-status`、`r4-authorization-preview`、`r4-bind`、`r4-run-batch`、`r4-review`、`r4-replay` 沿用现有 R4 入口。A 的批准不覆盖 B。

示例：

```bash
STAC_PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python bash scripts/attack_program/11_demo_r3.sh --output experiments/runs/attack-program/<new-id>
```

R1–R3 脚本不发送模型/API 请求，也不运行 Docker。R4 local-fake 脚本运行隔离 Docker/OpenClaw，向本机 fake provider 发送有界 HTTP；不访问真实模型。运行前用唯一 ID，脚本会拒绝覆盖已有输出。完成一次代码重构后使用新 ID 生成工程产物；历史 manifest 中的源码指纹对应原代码版本，不在新版本上修改或强行通过：

```bash
STAC_PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python bash scripts/attack_program/15_r4_fake_check.sh r4-fake-live-readiness-20260928-v1
```

查收 `experiments/runs/attack-program/r4-fake-live-readiness-20260928-v1-exit-code.txt`、同名目录的 `report.json` 和 `-external-audit/` 下三份 `audit.json`。三案实际 case 位于 `prepared/<candidate-id>/execution/case/`，同批 `binding.json`、`execution/activation.json`、`execution/terminal.json` 与 partial/cleanup 共同查收。返回 0 仍只表示本机 synthetic/fake 工程链通过。新版 fake 独立查收后才准备唯一新真实禁用候选。

无需 Docker 的回归入口是 `make check PYTHON=<project-python>`；它包括 Ruff、mypy 与纯离线/loopback HTTP 测试，不发真实模型请求。`make schemas PYTHON=<project-python>` 会生成合同 schema，只有合同变化时才需运行并审查差异。

本机 fake 查收后，准备并验证默认禁用的单个真实 development 候选：

```bash
STAC_PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python bash scripts/attack_program/13_r4_prepare.sh --candidate configs/attack_program/r4_development_candidate.json --output experiments/runs/attack-program/your-new-disabled-batch-id
STAC_PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python bash scripts/attack_program/14_r4_control.sh r4-validate --batch experiments/runs/attack-program/your-new-disabled-batch-id
```

prepared manifest `/2` 保持 `execution_enabled=false`、`binding=null`；绑定/激活/结果是独立不可覆盖文件。旧版本候选只读，需新目录重新 prepare，不迁移授权。`r4-status` 显示 disabled/prepared/bound/active/terminal/expired；active 或不确定发送先查 partial/cleanup 与 owned 资源，不自动重发。绑定有效期从 bind 开始，episode 从 activate 开始，cleanup 独立保留 120 秒。没有硬金额或总 token 上限。

`r4-authorization-preview --batch` 只返回待批准原文模板，不是批准。真实 bind/run 的两个必需参数是用户实际批准的 JSON 原文记录路径 `--authorization` 和该文件真实 SHA256 `--authorization-sha256`，并须显式真实授权旗标；本轮不提供可直接误执行的占位真实命令。fake prepare 使用 `--local-fake-mode normal|harm|reject`，只接受 `--local-fake-authorized`，不能用于 real。real bundle 的封存/重放还校验原批 binding/activation/claim，所以原批记录需与 case 一起保留。

邮件来源接受已核验目标文件的 `sim-google gmail get <filename> --json`，或先搜索后按唯一搜索 ID `get <id>` 的完整正文；两者均要求原始工具结果与对应 provider 调用、后续上下文引用。摘要、错误正文、缺证据保留 unknown；完整送达仍不等于语义采纳或因果贡献。

已关闭真实开发批次的只读诊断与受控导入：`r4-import-real-development --batch <原批次> --review <已封存查收目录> --audit <独立 replay audit.json>`。入口核对 prepared manifest、binding/activation/claim/terminal、候选和物化 hash、case 全文件 hash 及原独立 replay；派生目录固定为 `experiments/runs/attack-program/r4-real-development-imports/<source-manifest-hash>/`，包含安全诊断、真实 attempt、开发报告和哈希 manifest。重复导入返回同一 attempt，不增加分母。`r4-audit-real-development` 用同样三个参数重新计算并核对派生记录。输出仅列资产 ID 和受控字段，不包含 marker/私有文件正文；官方分数原样保留，独立 harm 只限其声明的响应 scope。此入口不调用模型、不绑定或重跑批次。
