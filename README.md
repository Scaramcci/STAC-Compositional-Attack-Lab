# STAC Compositional Attack Lab

本仓库研究组合攻击如何进入 Agent 系统、在组件之间传播、经过持久化或重组后影响后续行为，以及防御应部署在哪个传播节点。项目采用本地合成环境和无价值 canary，不执行真实外传、不读取真实凭证，也不允许被测工具访问宿主机或公网。

## 给审阅者的阅读顺序

1. 本页：研究思路、当前边界和实验运行状态。
2. [`docs/RESEARCH_STATUS.md`](docs/RESEARCH_STATUS.md)：已经实现、尚未实现和下一步需要修正的内容。
3. [`PROJECT_STRUCTURE.md`](PROJECT_STRUCTURE.md)：代码模块、角色隔离、数据流和产物说明。
4. [`docs/EXPERIMENT_PROTOCOL.md`](docs/EXPERIMENT_PROTOCOL.md)：当前实验协议及后续传播、防御实验设计。
5. [`docs/PROMPTS.md`](docs/PROMPTS.md)：Planner、Attacker、Victim、PromptWriter、Verifier、Judge 的权限和 prompt 契约。
6. [`SECURITY.md`](SECURITY.md)：安全边界。

## 当前研究对象

当前已实现并实际运行的是一类多阶段组合攻击，不是多种独立攻击的全集。其传播链为：

```text
不可信工具检索结果进入 Victim
  -> Victim 将相关内容写入 workspace memory
  -> 后续任务重新检索该 memory
  -> 内容影响工具参数
  -> 本地 action tool 处理合成 canary
```

这条链用于验证四个问题：攻击从哪里进入、是否跨组件传播、是否通过记忆形成跨阶段影响、最终行为是否可由完整 artifact lineage 解释。攻击成功与否由确定性 verifier 根据事件、artifact lineage 和环境快照判断，LLM Verifier/Judge 只提供语义说明，不能覆盖 hard verdict。

当前实现覆盖一个入口、一个线性传播拓扑、一种记忆介质和一个本地 canary sink。因此，它是后续系统化攻击图谱的第一类基线，不能表述为已经覆盖完整 Agent 攻击面。

## 对话数据在哪里

仓库保留了两组完整可观察对话，均为 JSONL，每行一个按 `sequence_no` 排序的事件。

### 离线样本构建对话

[`data/frozen/stac-verified-30-v0.1/conversations.jsonl`](data/frozen/stac-verified-30-v0.1/conversations.jsonl)

这里记录 GPT-5.5 Planner、Attacker、PromptWriter、Verifier、Judge 与 Gemini Victim 在样本构建阶段的请求和响应。对应的冻结样本位于：

- [`data/frozen/stac-verified-30-v0.1/samples.jsonl`](data/frozen/stac-verified-30-v0.1/samples.jsonl)
- `data/frozen/stac-verified-30-v0.1/verification/<candidate-id>/events.jsonl`
- `data/frozen/stac-verified-30-v0.1/verification/<candidate-id>/verdicts.jsonl`
- `data/frozen/stac-verified-30-v0.1/verification/<candidate-id>/artifacts/`
- `data/frozen/stac-verified-30-v0.1/verification/<candidate-id>/snapshots/`

### 正式 evaluation 对话

[`experiments/runs/evaluation_gpt_huihui_4090-02cb0b56baac/conversations.jsonl`](experiments/runs/evaluation_gpt_huihui_4090-02cb0b56baac/conversations.jsonl)

这里记录 GPT-5.5 Planner、Attacker、Verifier、Judge 与本地 Huihui-Qwen3 Victim 的交互，以及 Victim 与环境工具之间的 request/result、确定性 verifier 返回给 Planner 的阶段状态。每次攻击的环境事件和判定分别位于同目录的：

```text
<attack-id>/events.jsonl
<attack-id>/verdicts.jsonl
<attack-id>/report.json
```

`conversations.jsonl` 的关键字段包括：

- `attack_id`：所属攻击实例；
- `sequence_no`：全局对话顺序；
- `event_type`：model request/response、tool request/result、verifier result 或 error；
- `sender_role`、`recipient_role`：消息在组件之间的传播方向；
- `request_messages`、`raw_model_response`、`parsed_structured_response`：可观察输入、原始输出和结构化输出；
- `related_event_ids`、`artifact_refs`、`snapshot_refs`、`hard_verdict_refs`：对话与执行证据的链接；
- `prompt_id`、`prompt_hash`、`model_id`：prompt 与模型配置的可追溯信息。

仓库不请求或记录隐藏 chain-of-thought。`transcript_audit.json` 检查事件顺序、角色隔离、模型分配、链接完整性和敏感信息过滤。

## 当前实验运行状态

- 离线阶段已经构建并冻结 30 个通过完整执行和确定性验证的样本，版本为 `stac-verified-30-v0.1`。
- evaluation 已在服务器完成 30 个计划 episode，Planner/Attacker/Verifier/Judge 使用 GPT-5.5，Victim 使用本地 Huihui-Qwen3。
- 运行支持逐攻击 checkpoint、失败后 resume、append-only 进度日志和 transcript audit。
- 当前运行验证了上述单一攻击链的执行闭环；clean、ablation、defense 和更多攻击拓扑尚未进行正式模型实验。
- 当前结果只应视为系统工程与基线攻击链验证。传播因果分析、转折点定位和多防御比较仍是下一阶段工作。
- 下一版本离线收集配置为 configs/experiments/stac_sample_build_gpt_gemini_50.yaml（50 个 hard-pass，最多 200 个候选）；本次未运行任何真实模型调用。

## 已实现的系统能力

- 独立 Planner、Attacker、Victim、PromptWriter、Verifier、Judge 角色及 prompt/schema/model 配置；
- Pydantic 数据契约和生成的 JSON Schema；
- 攻击原语注册、攻击图验证和在线 STAC 状态机；
- 本地 `WorkspaceCanaryEnv`、事件日志、artifact lineage、状态快照；
- 不可被 LLM 覆盖的确定性 verifier；
- Fake、Gemini、OpenAI-compatible、Huihui/vLLM 模型客户端；
- 离线样本生成、审计、冻结和在线绑定执行；
- 每个攻击完成后持久化进度，配额中断后可恢复；
- 完整可观察对话记录与自动 transcript audit；
- 基础 clean、ablation、memory guard 和报告代码路径。
- SafeClaw no_sample 使用同一模板的合法 benign materialization，并保持 task/seed/budget/environment 配对。

## 尚未实现的研究扩展

- 多入口：用户输入、文件、Agent 间消息、Planner context、任务交接等；
- 多传播机制：摘要、改写、委派、参数序列化、跨会话召回等；
- 重组攻击：分片合并、多来源汇聚、可信与不可信内容混合、延迟触发；
- 多种图拓扑：分支、汇聚、反馈循环、跨 Agent、跨会话传播；
- 多种安全危害 sink 及统一严重度定义；
- 自动转折点检测、node/edge ablation 和因果贡献分析；
- 入口、memory、retrieval、Agent handoff、action sink 等多位置防御；
- 防御的 benign utility、误报、开销、绕过和自适应攻击评估；
- AgentDojo 与 SHADE_Arena 的正式实验集成，目前只有只读 adapter/contract smoke。

## 运行与复现

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
make lint
make typecheck
make test
make smoke-offline
make smoke-online
make smoke-report
```

Fake profile 不需要 API key 或网络。真实模型配置和运行命令见 [`docs/EXPERIMENT_PROTOCOL.md`](docs/EXPERIMENT_PROTOCOL.md)。凭证只从本地环境变量读取，不写入代码、配置、文档或日志。

正式样本采集与 SafeClaw 评估统一通过以下入口启动；两个入口都支持
`--help` 和 `--print-output-dir`，并使用稳定 run id、文件锁和持久日志：

```bash
bash scripts/run_sample_collection.sh
bash scripts/run_formal_evaluation.sh
```

样本默认写入配置 hash 派生的 `data/generated/<run-id>/`。SafeClaw formal
默认写入 `experiments/safeclaw_runs/safeclaw-formal-v1-main/`。

SafeClaw formal 配置已在授权后切换为 ready；启动入口仍会依次执行官方
PSE smoke、Docker/image/model preflight，并只接受配置 allowlist 中的 target model。
