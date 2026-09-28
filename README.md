# STAC Attack Program

本仓库当前实现 SafeClawArena 九原语样本库与多样本 Planner 的离线工程路线。R1–R3 支持安全物化、原始观测与独立裁决、synthetic 样本库、三臂多样本 Planner、独立 replay/audit；R4 本机 Docker/local-fake 三案已完成工程验收，真实开发候选仍默认禁用。合成正例只证明工程链，不代表真实模型攻击成功。

## 快速验证

项目解释器可通过 `PYTHON` 或 `STAC_PYTHON` 指定。例如：

```bash
make check PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python
make schemas PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python
make doctor PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python
STAC_PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python bash scripts/attack_program/11_demo_r3.sh --output experiments/runs/attack-program/<new-id>
```

R3 演示只运行 scripted Planner、synthetic 观测与离线官方检查。输出使用全新目录；`r3-replay --compare` 与 `audit-library` 可独立复算。R4 fake 使用隔离 Docker 和本机 fake HTTP，仍不发送真实模型请求。入口、环境要求与产物说明见 [scripts/README.md](scripts/README.md)，安全边界见 [SECURITY.md](SECURITY.md)，当前状态见 [docs/IMPLEMENTATION_PROGRESS.md](docs/IMPLEMENTATION_PROGRESS.md)。

真实模型/API、bind、正式研究库和正式实验需要单独的批次授权。当前没有独立 held-out test 组；合成工程报告不能用于三臂效果结论。
