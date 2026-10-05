# STAC Compositional Attack Lab

面向大模型智能体的**组合式提示注入研究仓库**：在固定版本的 SafeClawArena 任务中，限定可修改的外部材料，构造攻击候选，记录智能体行为，并通过官方检查、独立分析和重放审计建立可追溯证据。

研究问题是：把历史攻击材料组织为带有行为原语和证据关系的样本，是否有助于 Planner 在新任务中选择、组合攻击材料？当前仓库提供研究所需的工程链路；**尚不能据此宣称结构化样本优于原始样本，或已经完成正式泛化实验。**

## 当前能力与边界

| 层次 | 当前内容 | 结果应如何理解 |
|---|---|---|
| R1：任务与证据基础 | 固定任务目录、组级划分、允许修改的位置、安全物化、官方检查和独立裁决 | 校验材料、身份与证据，不以模型自述代替实际行为 |
| R2：开发与样本库 | 全部尝试记录、九原语状态、原文/结构化两种公开视图、synthetic 库和审计 | 合成库用于工程验证，不是正式研究库 |
| R3：Planner 比较 | `no_library`、`raw_examples`、`primitive_examples` 三臂，多样本选择与计划校验 | 离线演示使用脚本响应和合成观测，不测真实模型能力 |
| R4：运行适配 | 隔离 OpenClaw/Docker、provider relay、请求账本、候选封存、生命周期和独立重放 | 本机 fake 与真实开发批次分开，真实执行按批次授权 |

2026-10-05 文档审查时：仓库已有真实开发批次及查收记录，不能再描述为“从未运行真实模型”。最近的进度记录涉及 30-slot primitive-only 采集；本轮没有重跑或判定该批次完成。当前任务划分没有独立 held-out test 组，真实 structured 视图仍有证据稀疏限制。详细状态以[进度记录](docs/IMPLEMENTATION_PROGRESS.md)及对应批次证据为准。

## 从这里开始

- **第一次接触项目：** 阅读[项目结构与运行入门指南](docs/PROJECT_STRUCTURE_ZH.md)，从术语、代码目录到一次完整离线练习逐步学习。
- **准备整理仓库：** 阅读[清理审查清单](docs/rse/specs/research-repository-cleanup.md)，查看可删除缓存、可退役入口及仍被依赖的历史材料。
- **继续开发：** 阅读 [AGENTS.md](AGENTS.md)、[安全边界](SECURITY.md)、[当前计划](docs/IMPLEMENTATION_WORKPLAN.md)和[实验协议](docs/EXPERIMENT_PROTOCOL.md)。
- **查具体命令：** 使用[脚本说明](scripts/README.md)和 CLI `--help`；历史批次示例不是新的执行授权。

## 安装与离线快速开始

需要 Python **3.11 或更新版本**、Git、Bash；以下示例还使用 GNU Make。适合在 Linux 项目根目录执行。安装依赖会访问包源；安装后的以下演示不请求模型、不需要 API key、不启动 Docker。

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

此外，需要在 `integrations/safeclaw/upstream/SafeClawArena/` 放置固定 commit `a11f5cceaba0676be721021f8d232638fd111305` 的完整上游 Git checkout；该目录被 Git 忽略，安装 Python 包不会自动获取它。首次配置参见[入门指南](docs/PROJECT_STRUCTURE_ZH.md#4-准备环境)。不要覆盖本机已有 checkout。

```bash
make doctor PYTHON=python
make demo-r3 PYTHON=python RUN_ID="tutorial-r3-$(date +%Y%m%d-%H%M%S)-$$"
```

`doctor` 应返回 `offline_ready`。演示应报告 `engineering_only_synthetic`，包含 5 次 R2 开发尝试与 3 个 R3 已完成案例，Planner/Victim HTTP 均为 0。输出位于 `experiments/runs/attack-program/<RUN_ID>/`；摘要中的路径指向实际报告和审计文件。每次使用新 ID，不覆盖旧输出。

若已有项目环境，可以把 `PYTHON=python` 改为该环境解释器的完整路径，无需重复安装。

## 仓库布局

```text
src/stac_attack_lab/       Python 包：attack_program 主链及共享 HTTP client
configs/attack_program/   当前配置、任务划分和两个在用 prompt
schemas/                  从数据合同生成的 JSON Schema
scripts/attack_program/   离线包装、fake 验收及真实开发批次入口
tests/integration/        合同、语义、生命周期、HTTP 与审计测试
integrations/safeclaw/    pinned 上游 checkout 与独立安全补丁
docs/                     入门指南、协议、进度和历史设计记录
experiments/runs/         本地运行产物与证据；默认不进 Git
data/                     历史数据与库；保留复现依赖
```

R1–R4 是同一主链的不同层次，不能为了“只留 R4”删除 R1–R3。旧 capability/flow 等路线已不在当前源码主链中。最新批次脚本仍可能依赖较早脚本和历史冻结输入，详见清理清单。

## 验证与复现

先运行入门所需的离线专项：

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q \
  tests/integration/test_attack_program_pipeline.py \
  tests/integration/test_attack_program_r2.py \
  tests/integration/test_attack_program_r3.py
```

维护者质量门为 `make check PYTHON=python`，包括 Ruff、mypy 与测试。部分完整测试依赖本机封存实验和导入记录，因此不是仅安装依赖即可保证通过的干净克隆测试集。不要为得到全绿而删除历史数据依赖测试；先查明缺失输入。

`make schemas PYTHON=python` **会写入 schema 文件**，仅在修改数据合同时运行，并审查差异。2026-10-05 文档审查的实际验证及限制记录在[审查清单](docs/rse/specs/research-repository-cleanup.md)中，不以历史测试数字代替当前验证。

## 研究结果与数据管理

合成结果、本机 fake 结果和真实模型结果必须分开。运行完成、材料送达、状态写入、官方判分、独立危害判断及因果贡献是不同结论；`unknown` 或基础设施失败不能算作已验证的攻击失败。报告保留全部计划与尝试分母，不能只挑成功案例。

运行证据通常不随 Git 保存；备份仓库源码不等于备份实验。原始材料、请求账本、冻结 manifest、候选和来源批次应配套保存。公开分享前检查 public/private 边界，不上传 `.env`、凭证和私有 oracle。详见[安全边界](SECURITY.md)。

## 项目状态、许可与引用

这是持续开发中的研究原型，当前工作树包含未提交实现；引用或复现时应同时记录 commit、工作树状态、配置、prompt 与批次 manifest。仓库目前未提供根目录 LICENSE 或 CITATION.cff；对外分发前需由维护者明确许可与引用信息。上游组件遵循各自许可。本 README 不虚构论文、DOI、作者信息或开放许可。
