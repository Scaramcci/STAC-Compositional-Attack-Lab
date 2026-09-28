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
- `14_r4_control.sh`：R4 doctor、validate、status、bind、run-batch、review、replay 包装入口。bind/run-batch 当前拒绝执行。
- `15_r4_fake_check.sh`：三案 Docker/local-fake 总验收，保存退出码并运行独立 replay/audit；需本机 Docker、pinned OpenClaw 镜像与隔离网络。

示例：

```bash
STAC_PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python bash scripts/attack_program/11_demo_r3.sh --output experiments/runs/attack-program/<new-id>
```

R1–R3 脚本不发送模型/API 请求，也不运行 Docker。R4 local-fake 脚本运行隔离 Docker/OpenClaw，向本机 fake provider 发送有界 HTTP；不访问真实模型。运行前用唯一 ID，脚本会拒绝覆盖已有输出。完成一次代码重构后使用新 ID 生成工程产物；历史 manifest 中的源码指纹对应原代码版本，不在新版本上修改或强行通过：

```bash
STAC_PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python bash scripts/attack_program/15_r4_fake_check.sh "r4-fake-$(date +%Y%m%d-%H%M%S)"
```

查收 `experiments/runs/attack-program/<unique-run-id>-exit-code.txt`、同名目录的 `report.json` 和 `-external-audit/` 下三份 `audit.json`。返回 0 仍只表示本机 synthetic/fake 工程链通过；真实开发批次保持禁用。

无需 Docker 的回归入口是 `make check PYTHON=<project-python>`；它包括 Ruff、mypy 与纯离线/loopback HTTP 测试，不发真实模型请求。`make schemas PYTHON=<project-python>` 会生成合同 schema，只有合同变化时才需运行并审查差异。

本机 fake 查收后，准备并验证默认禁用的单个真实 development 候选：

```bash
STAC_PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python bash scripts/attack_program/13_r4_prepare.sh --candidate configs/attack_program/r4_development_candidate.json --output experiments/runs/attack-program/your-new-disabled-batch-id
STAC_PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python bash scripts/attack_program/14_r4_control.sh r4-validate --batch experiments/runs/attack-program/your-new-disabled-batch-id
```

`r4-bind` 与 `r4-run-batch` 当前固定拒绝执行；准备和验证不会发送真实模型请求。
