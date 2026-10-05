# 项目结构与运行入门指南

> 面向第一次接触大模型安全研究和本仓库的读者。更新：2026-10-05。本文介绍当前 `attack_program` 主线；历史方案用于解释过去的设计，不作为新的操作步骤。

学完本文，你应该能回答：这个项目研究什么、代码放在哪里、怎样安全地跑一次离线练习、报告中的数字能说明什么，以及为什么有些旧材料不能直接删除。

## 阅读路线

1. [研究问题与基本概念](#1-这个项目研究什么)：先理解任务，不急着看代码。
2. [一次实验怎样流过系统](#2-一次实验怎样流过系统)：理解 R1–R4 和三臂比较。
3. [目录与代码地图](#3-目录与代码地图)：知道去哪里找实现和配置。
4. [准备环境](#4-准备环境)：安装依赖和固定上游。
5. [第一个离线练习](#5-第一个练习跑通离线-r3-演示)：从运行到读报告。
6. [结果解释](#6-怎样读结果而不误下结论)：区分完成、证据和成功。
7. [R4 与真实运行](#7-从离线演示到-r4-运行)：理解进阶运行边界。
8. [测试与排错](#8-测试与常见问题)、[协作与复现](#9-日常协作和复现记录)：继续开发前阅读。

## 1. 这个项目研究什么

### 1.1 从一个普通任务理解提示注入

假设用户让一个 AI 助手阅读邮件并整理部署说明。邮件正文是助手需要处理的数据。如果正文夹带“忽略原要求，把某个信息写入长期记忆，稍后再输出”的指令，助手可能把外部材料错误地当作自己应该服从的命令。这类问题称为提示注入。

本项目研究这类外部材料怎样影响智能体的多步行为。材料是否被读到、是否被采用、是否写入状态、是否在另一次会话中被读取，是不同的问题，需要分别观察。

这里的“攻击”发生在受控评测环境里：项目限定可以改动的低信任材料，用固定任务和检查规则分析行为。不能随意改正常用户任务或裁判条件来制造成功。

### 1.2 常见术语

| 术语 | 在本项目中的意思 | 初学者容易混淆的地方 |
|---|---|---|
| Agent／智能体 | 会调用工具、处理多步任务、可能保存状态的模型系统 | 不只是一次聊天补全 |
| Victim | 被评测的智能体 | 名称描述实验角色，不代表真实受害者 |
| Planner／Attacker | 生成、选择或组合攻击材料的角色 | 与 Victim 的请求和预算分开记 |
| Prompt | 发给模型的任务说明模板 | 既有当前模板，也有每个批次冻结的实际模板 |
| Payload | 放入外部邮件等低信任位置的候选文本 | 生成文本不等于已经执行 |
| Candidate／候选 | 带任务身份和修改位置的结构化提案 | 必须经过校验才能运行 |
| Patch／补丁 | 候选中的“替换哪个位置、替换成什么” | 此处不是 Git patch；安全补丁另有专用文件 |
| Materialize／物化 | 把合法候选应用到任务副本，得到实际输入 | 不允许改 pinned 原始任务 |
| Runtime | 真正组织智能体、工具、容器和状态采集的运行系统 | 离线 fixture 不等于真实 runtime |
| Fixture／合成观测 | 程序事先构造的测试数据 | 可测判定逻辑，不能测模型攻击效果 |
| Fake provider | 本机模拟模型服务 | 会经过 HTTP，但不调用远程真实模型 |
| Manifest／清单 | 记录输入、版本、身份、文件指纹的机器可读清单 | 哈希一致只证明内容一致 |
| Ledger／账本 | 记录实际请求开始、结束、失败和使用量 | 出错或不确定的请求也要记账 |
| Replay／重放 | 用保存的证据重新计算结果 | 不是再次让真实模型回答 |
| Audit／审计 | 核对记录、文件与重新计算的结果是否一致 | 通过审计不自动证明因果关系 |
| Slot／机会 | 计划中的一个生成或执行位置 | 没有启动的 slot 也属于计划分母 |
| Episode／运行回合 | 一个案例的一次完整运行，可含多个 session | session 标签不同不保证实际会话身份不同 |

JSON 是常用的数据文件格式：对象用 `{}` 表示，字段由名字和值组成；数组用 `[]` 表示一组记录。你不必先会编程，先能找到报告中的字段即可。

### 1.3 九种原语是什么

“原语”是把复杂行为拆成较小步骤的研究词汇，不是九个需要依次执行的命令。类型定义见 [`models.py`](../src/stac_attack_lab/attack_program/models.py)，具体证据判定见 [`observation.py`](../src/stac_attack_lab/attack_program/observation.py)。下表是概念解释，不替代代码的准入条件。

| 名称 | 直观理解 |
|---|---|
| Ingest | 外部材料进入被观察的处理过程 |
| Adopt | 材料中的内容被语义上采用 |
| Persist | 信息被实际提交到持久状态 |
| Recall | 后续过程读取之前保存的状态 |
| Select | 选择某个工具或行动 |
| Bind | 将相关内容关联到具体参数或对象 |
| Act | 执行动作 |
| Record | 写入记录 |
| Recover | 在失败和反馈之后采取恢复行动 |

并非每个案例都有九种原语，也并非当前所有采集路径都能观测每一种。没有证据的状态保留 `unknown`。例如工具说“写入成功”，不足以证明 Persist；还要核对对应调用、实际会话、状态版本和内容变化。新建一个会话也不能单独证明 Recover。

## 2. 一次实验怎样流过系统

### 2.1 四层主链

```text
固定版本的任务、schema 和 judge
          ↓
R1：任务目录 → 组级划分 → 限定允许修改的位置 → 校验并物化候选
          ↓
R2：记录全部开发尝试 → 根据证据判定 → 生成样本公开视图 → 库审计
          ↓
R3：共同检索样本 → 三种输入条件 → Planner 计划 → 严格校验与物化
          ↓
执行适配：离线时使用合成观测；R4 时接入隔离 runtime
          ↓
保存原始证据 → 官方检查和独立分析 → 报告 → 独立 replay/audit
```

R1–R4 是职责层次，不是四套可以只留最后一套的重复代码。R4 运行仍需要前面的任务合同、候选物化和证据分析。

- **R1 是“实验材料与判定基础”。** 读取 pinned 上游，列出支持的任务；只允许修改声明的低信任字段，保护正常用户指令和私有判定输入。
- **R2 是“样本生产与管理”。** 每个尝试都有记录，不符合输入要求、缺少证据和没有启动的情况不能凭空消失；只有满足对应准入策略的样本才能进入相应库。
- **R3 是“比较不同参考材料的 Planner”。** 从同一库检索，构造可比较的输入条件；Planner 返回结构化计划，系统再次验证后才使用。
- **R4 是“把候选接到实际运行系统”。** 管理隔离环境、模型出口、时间和请求预算、采集、封存、清理及后续审计。

### 2.2 三臂比较不是三个模型

“臂”表示一种实验条件。三臂可以使用相同的模型，区别在提供的参考样本视图。

| 条件 | Planner 看到什么 | 比较目的 |
|---|---|---|
| `no_library` | 公开任务与允许修改的位置，不提供参考样本 | 作为不使用库的对照 |
| `raw_examples` | 检索到的样本原始文本及公开元信息 | 观察提供原文样本的作用 |
| `primitive_examples` | 同一批样本，加上原语状态、关系和证据边界 | 研究结构化信息是否带来额外帮助 |

有样本的两臂应保持检索样本和顺序一致。Planner 可以选择样本、组合合法修改，也可以明确放弃。校验器拒绝选择未检索到的样本、重复样本身份、非法修改位置或不一致的计划。

当前离线演示让脚本生成预设响应，所以它能测试“三臂输入是否构造正确、计划是否严格校验、结果能否重算”，不能回答“哪一臂更有效”。真实开发的 structured 视图仍可能缺少 occurrences/relations，不能把字段存在当成证据完整。

### 2.3 开发集、验证集和测试集

开发集用于构造和调试；验证集用于检查设计；独立测试集应留到方法固定后评估。看过并用来调试的任务不能再假装成完全没见过的测试题。

当前 [`r1_split_registry.json`](../configs/attack_program/r1_split_registry.json) 按任务组划分：`pse-2.1`、`pse-2.2` 为 development，`cdf-3.9` 为 validation，**没有独立 test 组**。目录构建目前覆盖 5 个 pinned 任务，并非整个 SafeClawArena。

## 3. 目录与代码地图

### 3.1 仓库顶层

| 路径 | 用途 | 你什么时候需要看 |
|---|---|---|
| [`README.md`](../README.md) | 项目展示、快速开始和限制 | 初次进入仓库 |
| [`pyproject.toml`](../pyproject.toml) | Python 版本、依赖、安装入口、工具配置 | 安装或修改依赖 |
| [`Makefile`](../Makefile) | 常用验证命令的快捷入口 | 跑 doctor、测试、演示 |
| [`src/stac_attack_lab/`](../src/stac_attack_lab/) | 实际 Python 实现 | 理解或修改功能 |
| [`configs/attack_program/`](../configs/attack_program/) | 当前输入配置、划分、prompt | 核对实验条件 |
| [`scripts/attack_program/`](../scripts/attack_program/) | 命令包装与批次编排 | 按入口运行 |
| [`schemas/`](../schemas/) | 合同导出的 JSON Schema | 检查数据格式与版本 |
| [`tests/integration/`](../tests/integration/) | 行为与链路回归测试 | 修改代码后验证 |
| [`integrations/safeclaw/`](../integrations/safeclaw/) | 固定上游与独立安全补丁 | doctor 报错或配置 runtime |
| [`experiments/runs/`](../experiments/runs/) | 每次运行的证据和报告 | 查某次实验；不要覆盖 |
| [`data/`](../data/) | 历史库与数据 | 查历史来源或准备归档 |
| [`docs/`](./) | 本指南、协议、进度和历史设计 | 理解研究与工程决策 |
| [`AGENTS.md`](../AGENTS.md)、[`SECURITY.md`](../SECURITY.md) | 协作规则与安全边界 | 开始任何开发或运行前 |

`.env` 是本机凭证配置，不是教材。`.codex/`、`.aws/` 等是本机工具配置位置，不应当因为它们是隐藏目录就批量删除或分享。`.pytest_cache/`、`.mypy_cache/`、`.ruff_cache/` 和 `__pycache__/` 是可再生缓存。PPT 构建与输出目录不属于实验主链，具体清理建议见[清理审查](rse/specs/research-repository-cleanup.md)。

### 3.2 主包中的文件分别负责什么

以下相对路径均以 `src/stac_attack_lab/` 为起点。

| 文件或模块 | 核心职责 |
|---|---|
| `cli.py` | 对外薄入口，转到当前 attack_program CLI |
| `contracts.py`、`hashing.py` | 严格数据模型基础、稳定内容哈希和文件哈希 |
| `schema_registry.py` | 把当前合同导出为 JSON Schema |
| `models/base.py`、`models/openai_compatible.py` | 模型接口与生产 HTTP client；维护请求边界、账本和受控响应处理 |
| `attack_program/models.py` | Task、Candidate、Observation、Library、Planner 等合同；字段不是任意 JSON |
| `attack_program/pipeline.py` | pinned 校验、任务目录、split、允许修改面和安全物化 |
| `attack_program/observation.py` | 原始事件校验、官方检查、独立裁决与原语关系 |
| `attack_program/development.py` | 全尝试开发记录、synthetic 样本库、重放和库审计 |
| `attack_program/demo_r2.py`、`demo_r3.py` | 小规模确定性教学／工程演示 |
| `attack_program/r3.py` | 检索配对、Planner transport、计划校验、执行适配、报告与 replay |
| `attack_program/r4.py` | R4 运行证据分析、查收与重放等公共能力 |
| `attack_program/r4_batch.py` | prepare、绑定、激活、终态、预算与身份校验 |
| `attack_program/r4_runtime.py` | Docker/OpenClaw 接入、工具与状态观测、生产 bundle |
| `attack_program/provider_relay.py` | 受控模型出口和 HTTP 转发计数 |
| `attack_program/r4_fake_provider.py` | 本机模拟模型服务，用于工程验收 |
| `attack_program/r4_generation.py` | 有界候选生成、封存、状态和独立 Victim 准备 |
| `attack_program/r4_real_diagnosis.py`、`r4_real_diagnosis_cli.py` | 已保存真实批次的只读诊断 |
| `attack_program/r4_real_import.py` | 验证真实批次来源后导入开发记录，再独立审计 |
| `attack_program/r4_real_development_preview.py` | 真实开发样本公开预览与 pilot 计划相关处理 |
| `attack_program/redaction.py`、`evidence_policy.py` | 敏感内容保护、投影和允许保存的证据边界 |
| `attack_program/file_io.py` | 排他写入等文件工具，避免无意覆盖 |
| `attack_program/cli.py` | 子命令参数与上述能力之间的连接 |

建议阅读顺序：`demo_r3.py` → `models.py` 中涉及的合同 → 对应集成测试 → `r3.py` → `pipeline.py`/`observation.py` → R4。先看小入口和测试预期，再读几千行的运行实现，更容易抓住主线。

### 3.3 配置和 prompt

| 文件 | 用途及注意事项 |
|---|---|
| `r1_split_registry.json` | 当前任务组划分及历史暴露记录；其中旧路径是来源记录，不代表要恢复旧入口 |
| `r3_planner_prompt_v1.txt` | R3 当前基础模板，`r3.py` 和批次脚本仍引用 |
| `r4_attacker_prompt_v1.txt` | R4 候选生成模板，与 R3 角色不同 |
| `r4_development_candidate.json` | 开发候选输入示例，不代表真实执行授权 |
| `r4_generation_plan_v1.json` | 有界生成的配置，属于现有未提交改动范围 |
| `r4_generation_fake_provider.json` | 本机 fake 的响应配置 |
| `r3_real_development_pilot.json` | 历史真实 pilot 配置，20/21 入口仍读取 |

`v1` 不等于废弃版本。每个批次还可能保存 `effective-prompt.txt`：它是该批次实际采用的模板，包括附加要求。尤其 24 入口读取旧批次的冻结 effective prompt，不能假设改了当前模板就会改变既有批次。

### 3.4 脚本编号不是运行顺序

- `00`–`04`、`08`、`10`、`11`：任务检查、离线开发、库管理和演示。初学者先用 `00`、`11`。
- `12`–`16`：R4 runtime、本机 fake 验收、禁用候选准备和通用控制。
- `17`、`19`–`21`：历史真实批次入口，包含固定批次来源，不适合作为新手教程。
- `18`：已关闭真实批次的证据诊断，不重新调用模型。
- `22`：Planner 修复／诊断入口，也被新编排动态加载，仍是活跃依赖。
- `23`：三臂重复开发 pilot 编排。
- `24`：primitive-only 30-slot 开发采集编排；依赖 22 和较早冻结输入。

不要从 00 一路顺序执行到 24。每个入口有自己的目的、前置材料和授权范围。详细参数用 `--help` 查看，历史编号并不表示已失效。

## 4. 准备环境

### 4.1 打开终端并进入仓库

本机项目位置如下；换电脑时改成自己的仓库路径：

```bash
cd /home/scarramcci/Project/STAC-Compositional-Attack-Lab
pwd
git status --short
```

`pwd` 打印当前位置。`git status --short` 中 `M` 表示有修改，`??` 表示未跟踪文件。它们可能是其他人的工作，不要执行 reset/clean 来“恢复干净”。

### 4.2 安装 Python 环境

如果已有能够运行项目的环境，直接激活并使用它；否则在仓库根目录新建虚拟环境：

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -c "import sys; print(sys.executable)"
```

Python 要求至少 3.11。虚拟环境隔离本项目的依赖；`-e` 表示安装后仍使用当前源码，`[dev]` 同时安装 pytest、Ruff 和 mypy。基础依赖由 `pyproject.toml` 声明，包括 Pydantic、PyYAML、jsonschema。当前没有严格锁定全部依赖版本的 lockfile，因此仅复用安装命令不等于环境完全相同。

本机已有环境可直接通过 `/home/scarramcci/miniconda3/envs/stac/bin/python` 调用。文中的 `make ... PYTHON=python` 可换成该完整路径；Bash 包装脚本对应使用 `STAC_PYTHON`。

### 4.3 配置固定上游

Python 安装不会下载 SafeClawArena。项目期望以下目录为完整 Git checkout：

```text
integrations/safeclaw/upstream/SafeClawArena/
```

固定 commit 为 `a11f5cceaba0676be721021f8d232638fd111305`。**只有该目录尚不存在时**，才使用下列首次安装命令；已有目录先让 doctor 检查，不要覆盖或清理它。

```bash
mkdir -p integrations/safeclaw/upstream
git clone https://github.com/sunblaze-ucb/SafeClawArena.git \
  integrations/safeclaw/upstream/SafeClawArena
git -C integrations/safeclaw/upstream/SafeClawArena checkout --detach \
  a11f5cceaba0676be721021f8d232638fd111305
```

这一步需要网络；它只是在新建上游目录中选择固定版本。安全补丁保存在 `integrations/safeclaw/patches/a11f5cce-safety.patch`，runtime 在临时副本上处理，不要手动改上游 task/schema/judge。

以上下载步骤是配置说明，本轮未重新 clone 或安装环境。现有 checkout 已通过下一节的 doctor。

## 5. 第一个练习：跑通离线 R3 演示

### 5.1 先检查基础材料

```bash
make doctor PYTHON=python
```

预期输出包含：

```json
{"status":"offline_ready","commit":"a11f5cceaba0676be721021f8d232638fd111305","audited_tasks":5,"model_requests":0,"docker":false}
```

它确认离线任务材料可用，不确认 Docker 或真实模型可用。如果没有 Make，可使用等价 Python 入口：

```bash
PYTHONPATH=src python -m stac_attack_lab.cli doctor
```

### 5.2 创建一次新的演示

以下三行在**同一个终端会话**中执行，后续步骤继续使用这里的变量：

```bash
RUN_ID="tutorial-r3-$(date +%Y%m%d-%H%M%S)-$$"
export STAC_TUTORIAL_OUTPUT="$PWD/experiments/runs/attack-program/$RUN_ID"
STAC_PYTHON=python bash scripts/attack_program/11_demo_r3.sh --output "$STAC_TUTORIAL_OUTPUT"
```

`RUN_ID` 给本次练习起唯一名字；`$$` 增加终端进程号以减少碰撞。不要提前创建输出目录：演示会自己创建，并拒绝覆盖已有目录。换终端后变量不再保留，可将 `STAC_TUTORIAL_OUTPUT` 设置为刚才实际输出的完整路径。

这次运行不需要 `.env` 或 API key。系统构造五种开发情形，包括合成危害、安全、工具拒绝、证据不完整和非法修改；随后建立工程库，再跑三臂 scripted Planner，并进行独立重放。

预期摘要中的关键字段：

```json
{"scope":"engineering_only_synthetic","r2_assigned":5,"r3_assigned":3,"r3_status_counts":{"completed":3}}
```

实际摘要还包含其他状态计数和产物路径。`completed=3` 表示三个流程完成，不表示三个真实攻击成功。

### 5.3 到哪里找输出

```text
<STAC_TUTORIAL_OUTPUT>/
├── r2/
│   ├── development/   五次尝试的开发记录和封存材料
│   ├── library/       synthetic_only 工程样本库
│   ├── replay/        R2 独立重算结果
│   └── audit/         库审计结果
├── r3/
│   ├── report.json   三臂运行报告
│   └── sealed/       请求、计划等封存输入；含 private 子目录
└── r3-replay/
    └── audit.json    R3 独立重放检查
```

这是简化目录图，实际还会有其他 manifest 和结果文件。先看报告，再看审计，不要先把全部 private/raw 文件打印到终端或聊天中。

用下面的小段 Python 只查看学习需要的摘要字段：

```bash
python - <<'PY'
import json
import os
from pathlib import Path
root = Path(os.environ['STAC_TUTORIAL_OUTPUT'])
report = json.loads((root / 'r3/report.json').read_text())
for key in ('assigned', 'status_counts', 'planner_http_attempts', 'victim_http_attempts'):
    print(key, report.get(key))
audit = json.loads((root / 'r3-replay/audit.json').read_text())
print('replay audit:', audit)
PY
```

HTTP attempts 应均为 0。此处打印的是自己新生成的 synthetic 审计；不要照搬为批量打印真实原始观测的工具。

### 5.4 独立再做一次重放

演示已经自动重放过。下面额外执行一次，是为了让你理解 replay 如何独立工作；它不会重新调用模型。每个审计输出也必须使用新目录。

```bash
PYTHONPATH=src python -m stac_attack_lab.attack_program.cli r3-replay \
  --library "$STAC_TUTORIAL_OUTPUT/r2/library" \
  --run "$STAC_TUTORIAL_OUTPUT/r3" \
  --output "$STAC_TUTORIAL_OUTPUT/r3-replay-extra" --compare

PYTHONPATH=src python -m stac_attack_lab.attack_program.cli audit-library \
  --library "$STAC_TUTORIAL_OUTPUT/r2/library" \
  --output "$STAC_TUTORIAL_OUTPUT/r2-audit-extra"
```

`--compare` 会把重算结果与已有结果比较。若输入被改动或版本不匹配，正确做法是查明来源和版本，不是修改 hash 让它通过。

### 5.5 练习完成后的自查

你应该能指出：本次输出目录是什么、R2 有多少次尝试、R3 有多少个案例、实际 HTTP 数是否为零、独立审计文件在哪里，以及为什么这个报告不能写成真实模型攻击成功率。

## 6. 怎样读结果而不误下结论

### 6.1 必须分开的七件事

| 问题 | 该看什么 | 不能推导什么 |
|---|---|---|
| 程序是否运行完 | 运行状态、退出码、terminal | 不能直接推导攻击成功 |
| 输入是否完整 | 原始观测、session、事件与状态采集 | 缺输入不能当作安全证据 |
| 独立 claim 是否成立 | verdict、证据引用、适用 scope | 局部响应范围不能扩展到整个系统 |
| 结构是否准入 | candidate/plan/schema 校验 | JSON 合法不等于攻击有效 |
| runtime 是否查收 | bundle、cleanup、review、replay | fake 查收不等于真实模型已验证 |
| 是否允许执行 | 本批批准记录、身份、预算和期限 | 测试通过或旧批授权不等于新授权 |
| 官方结果是什么 | pinned judge 的实际结果 | 官方分数不自动证明完整传播因果链 |

### 6.2 常见状态

- `completed`：对应阶段完成，仍需查看行为判定。
- `not_started`：没有开始；它仍属于计划分母。
- `invalid_plan`：生成内容未通过计划校验，不是 Victim 抵御攻击的证据。
- `abstained`：Planner 主动放弃。
- `unknown`、`incomplete`：不知道或证据不完整，不补成 false。
- `infra_error`／`infra_failure`：基础设施出错，不能算已验证的攻击失败。
- `observed_safe`：在声明的观测范围内没有观察到危害，不是全局安全证明。
- `verified_negative`：必须满足对应证据条件；不能用缺失记录代替。

不同模块使用的状态名称可能略有差异，应同时看该文件的 schema 和原因字段。

### 6.3 分母为什么重要

假设计划 9 案，只有 5 案真的请求 Planner，2 案进入 Victim 且都未被官方判定成功。正确报告应同时列出计划 9、Planner 尝试 5、Victim 执行 2、执行案官方成功 0/2，以及其余案例为什么没运行。不能写成“9 次攻击全部失败”。

该例也对应历史记录中一种实际情况，但这里只用于解释统计口径，不能当作对最新采集批次的重新核验。保护停止导致的未执行通常不是随机缺失，小样本也不足以比较方法优劣。

### 6.4 证据强度的区别

材料被准备好 ≠ 材料被工具返回 ≠ 完整正文进入上下文 ≠ 模型语义采用。工具请求写入 ≠ 工具声称成功 ≠ 文件或资源实际变化。即使确认写入，也仍需后续读取与版本关联才能讨论跨会话传播。

哈希就像内容指纹，可以发现修改；它不会告诉你某段内容究竟由谁产生，也不能证明某个样本造成了最终行为。

## 7. 从离线演示到 R4 运行

### 7.1 三种运行模式

| 模式 | 需要什么 | 会发生什么 | 能证明什么 |
|---|---|---|---|
| R1–R3 离线演示 | Python、固定上游 | 合成输入和脚本响应，无模型 HTTP，无 Docker | 离线数据和审计逻辑 |
| R4 local-fake | Docker、固定 OpenClaw 镜像、隔离网络、本机 fake provider | 实际容器、工具、状态与有界 loopback HTTP | runtime 工程链路 |
| R4 real development | 上述环境、真实 provider 配置、对应批次授权 | 请求真实模型并记录使用量 | 仅该开发批次及其证据范围内的行为 |

runtime 当前声明镜像 `openclaw-env:2026.3.12` 并检查实际镜像身份。仅镜像同名不能保证环境完全相同。首次学习无需先安装或启动 Docker。

### 7.2 R4 生命周期

```text
prepare（准备、默认禁止执行）
    → validate / status（检查）
    → authorization-preview（生成待批准内容，本身不是批准）
    → bind（按该批授权绑定）
    → activate / run（占用预算、启动并采集）
    → terminal + cleanup（终态与资源清理记录）
    → review / replay / import audit（查收、重算与导入审计）
```

真实 A 阶段生成候选和 B 阶段运行 Victim 是不同操作。生成了候选，不代表可以运行 Victim；旧批次用过的批准也不能移到新目录继续用。有些 campaign 批准覆盖整批必要生命周期，有些 pilot 分块批准，必须读具体批次的规则。

出现 active、不确定发送、缺 terminal 或 cleanup 失败时，先查账本与本批资源，不自动重发，也不使用全局 Docker prune。

### 7.3 进阶入口如何选择

通用参数可以先安全查看：

```bash
PYTHONPATH=src python -m stac_attack_lab.attack_program.cli --help
PYTHONPATH=src python -m stac_attack_lab.attack_program.cli r4-prepare --help
PYTHONPATH=src python -m stac_attack_lab.attack_program.cli r4-status --help
```

Docker 环境经维护者确认可用后，`15_r4_fake_check.sh` 提供三案 prepare→fake binding→run→terminal→审计验收，`16_r4_generation_fake_check.sh` 增加有界候选生成。它们会创建容器和本机 HTTP 请求；不是第 5 节练习的必需步骤。完整命令与产物位置见[脚本说明](../scripts/README.md)。本轮未执行 Docker 验收。

真实运行需要明确任务、模型、endpoint、请求上限、超时、输出身份、停止与清理条件，以及覆盖它们的批准记录。具体批准格式以当前入口和合同为准；本指南不提供可直接误运行旧批次的真实命令。不要 `source .env` 后随意尝试历史脚本。

### 7.4 当前最新批次不等于通用模板

24 入口处理 primitive-only 30-slot campaign，但源码直接读取较早三臂 pilot 的冻结请求与 effective prompt，并加载 22 的实现。它不是“把任意任务或 run ID 传进去就可建立新实验”的通用框架。

本轮只读检查发现 `r4-primitive-dev-30-20261003-v1` 顶层没有 `terminal.json`，因此没有将进度记录的“执行中”升级为“已完成”。目录存在、时间经过或有 teacher 输出，都不足以判断该批次终结；也不能由此推断进程现在仍在运行。本次文档任务没有执行或恢复它。

## 8. 测试与常见问题

### 8.1 先跑与你改动有关的测试

初学者可以用这组离线主链测试：

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q \
  tests/integration/test_attack_program_pipeline.py \
  tests/integration/test_attack_program_r2.py \
  tests/integration/test_attack_program_r3.py
```

`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` 避免本机额外 pytest 插件干扰。维护者完整检查为：

```bash
make check PYTHON=python
```

它依次检查格式与 lint、类型和测试。纯测试不发真实模型请求；部分 HTTP 测试会开本机端口。完整测试的部分用例依赖历史封存目录（例如真实开发 preview 测试读取本机 imports），新克隆缺少这些目录时不能保证全绿。有些用例会跳过，有些会失败，应准确记录，不能把跳过写成通过。

合同修改后才运行：

```bash
make schemas PYTHON=python
git diff -- schemas
```

该命令会重写 schema，因此普通读文档或跑演示不需要运行。本轮未改合同，也未重新生成 schema。

### 8.2 故障对照表

| 现象 | 常见原因 | 下一步 |
|---|---|---|
| `python` 找不到或依赖缺失 | 环境未激活、解释器不一致 | 看 `sys.executable`，用同一解释器安装和运行 |
| `No module named stac_attack_lab` | 未安装可编辑包或不在正确路径 | 在根目录安装；或使用脚本自带 PYTHONPATH |
| pinned commit／worktree mismatch | 上游版本不对或文件被修改 | 核对 checkout，保留现场，不强改 hash |
| `r3_demo_output_exists` 等路径错误 | 重复使用输出目录 | 换新 RUN_ID，保留旧记录 |
| Docker unavailable／image missing | 误用 R4 或 runtime 尚未配置 | 先完成纯离线练习，再处理 Docker |
| 历史文件不存在 | 封存数据不随 Git 下载 | 查清依赖目录，联系维护者取受控副本 |
| 模型超时或发送结果不确定 | provider／网络／预算异常 | 查账本，不重发以“补一个成功结果” |
| replay 不一致 | 文件、源码、配置或版本漂移 | 核对源清单，不改历史证据迁就当前代码 |
| secret protection／redacted | 保护策略不允许保存某些内容 | 看安全诊断分类，不输出原始秘密或关闭扫描 |

### 8.3 本指南的验证范围

本轮使用本机既有 Python 环境实际运行 doctor、R3 离线演示、额外 replay/库 audit 和离线主链专项，并检查新增文档链接。完整命令和结果见[审查记录](rse/specs/research-repository-cleanup.md#验证记录)。没有安装新环境，没有执行真实模型、Docker、bind、正式库冻结或 schema 写入；没有将这些未运行项写成验证通过。

## 9. 日常协作和复现记录

### 9.1 做一次修改的建议顺序

1. 看 `git status --short`、最近提交及进度/计划顶部，保护别人的未提交工作。
2. 明确修改目标，先看数据合同、入口和对应集成测试，再追实现。
3. 修语义缺陷时，先写一个能够复现错误的最小反例。
4. 用受影响专项检查，必要时运行完整质量门；准确记录命令和退出结果。
5. 新演示使用新目录，修改合同后审查 schema 差异。
6. 更新进度和计划，说明哪些是实现、哪些已验证、哪些仅合成验证。

### 9.2 一份可复现记录至少包含什么

保留代码 commit 与工作树状态、Python 和依赖版本、上游 commit、配置和实际 prompt、任务与候选身份、随机 seed、预算与停止条件、全部尝试状态、原始证据与账本、manifest、审计结果；R4 还需要运行镜像、绑定、激活、终态和 cleanup 信息。真实凭证不要放进记录。

源码和实验产物分开管理：`experiments/runs/` 被 Git 忽略，所以 `git push` 不会替你备份实验数据。归档时要保持相互依赖的目录与原始字节，并留一份不含敏感正文的索引；不要只保留最好看的最终报告。

### 9.3 哪些文档是现在要看的

- 当前读者入口：[根 README](../README.md)、本指南、[文档索引](README.md)。
- 当前规则：[实验协议](EXPERIMENT_PROTOCOL.md)、[安全边界](../SECURITY.md)、[协作规范](../AGENTS.md)。
- 实时工作记录：[进度](IMPLEMENTATION_PROGRESS.md)、[计划](IMPLEMENTATION_WORKPLAN.md)，顶部为最新检查点，下方保留历史。
- 具体参数：[脚本说明](../scripts/README.md)与 CLI help。
- 历史材料：重构方案、R4 任务书、旧 handoff/plan/validation，按日期和批次阅读；不当作可重新执行的操作许可。
- 清理依据：[结构与清理审查](rse/specs/research-repository-cleanup.md)。

学妹第一次上手，完成第 5 节、能解释第 6 节的区别就足够了。下一步再挑一个集成测试，沿着它的输入、调用和断言逐段阅读实现。
