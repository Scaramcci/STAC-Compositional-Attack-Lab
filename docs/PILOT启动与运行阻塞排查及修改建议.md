# Pilot 启动与运行阻塞：排查结论及修改建议

审查基线：`f33c74e`，本地工作树起始干净。审查只读源码和既有记录，执行了 benign/preflight/admission 专项 **11 passed**，没有启动 Docker 实验、真实 API 请求或 pilot。本文件不是服务器当前在线状态诊断，也不是新的调用授权。

## 1. 核心结论

“无法启动 pilot”不是一个统一错误。当前至少要分开：实现缺失、入口走错、预检查阻塞、真实请求失败、预算中断、产物证据不够、运行时审核待定。

**当前本地代码尚未完成整个新研究流程。** Stage A 正常采集只有 synthetic fixture；新正常模式的真实 SafeClaw runtime、正常路径库冻结、graph-prior 正式执行尚未接通。若服务器已完成后续代码，应先同步实际 HEAD/差异再重新判断，不能将本地缺失断言为服务器缺失。

旧 pilot 是 adversarial collection，不是用户现在需要的 benign pilot。启动旧脚本即使成功，也不能证明新流程已完成。

## 2. 已确认阻塞与风险

### P0-A：正常采集只有 fixture 实现

证据：

- `src/stac_attack_lab/cli.py` 的 benign 子命令只有 `validate`、`prepare`、`collect-fixture`。
- `execution/benign_collection.py` 的 `collect_benign_fixture` 拒绝非 synthetic source 和 enabled execution。
- `docs/IMPLEMENTATION_WORKPLAN.md` 当前部分明确 Stage B/C 尚待实现，真实正常采集需补 runtime mapping。

结论：不能通过把 execution_enabled 改为 true 获得真实 benign pilot。此时应报告 `implementation_missing`，而不是指导用户不断重跑或扩大额度。

建议：新增正常 SafeClaw adapter 与明确的 benign live 入口，复用现有 driver/relay/账本，但正常策略不得接入旧攻击目标。若暂不实现，应在统一诊断中明确阻塞和正确下一步。

### P0-B：默认脚本仍指向旧路线

`scripts/run_safeclaw_sample_collection.sh` 默认读取 `configs/sample_generation/pilot_collection.yaml`；该配置仍是 adversarial_trace，且 execution_enabled=true。它不是 Stage A 的正常配置。

建议：入口明确显示 `workflow_kind`、source mode、是否真实调用、配置路径和运行目标。不要把旧入口悄悄改成不同语义；提供明确 benign 入口，将旧脚本标为 legacy。新入口默认 disabled。执行权限独立检查，不能拿配置中的 true 当会话授权。

### P0-C：运行成功与准入失败被用户看成同一种失败

既有 `construction-cross-session-20260915-214932-33f82859`：

- status=complete，failure_category=null；
- Attacker/Victim/Embedding attempts=8/16/0；
- candidate/accepted/negative=1/1/0；
- quality/preflight/construction/mine/audit exit=0；
- admission exit=1；
- 失败门为 cross_session_persistence_read_use；runtime_budget_isolation_cleanup_review=pending。

这是旧批次工程运行完成、证据门未满足，不是 Docker 未启动，也不是仍在报502。旧结果不能用当前新 verifier 回写为通过。

建议：顶层总览同时显示 execution、artifact integrity、profile、runtime review、authorization；给具体 failed/pending gates 和证据位置。普通 benign pilot 不应强制通过跨会话或强消费 profile；声称跨会话能力的样本仍须严格验证，不能降低原证明义务。

### P1-D：preflight 聚合丢失具体原因

`execution/revalidation.py:launch_live_revalidation` 在 preflight 未通过时仅抛出 `revalidation_live_preflight_failed`；启动失败摘要未保存完整 check report。原报告已有详细 reason_codes，外层丢失它们导致用户只看到笼统失败。

`execution/sample_preflight.py` 又把 execution_enabled 纳入统一 passed。对禁用配置做准备性检查时，“尚未启用”容易被误解为环境坏了。

建议：无论通过与否先原子保存脱敏完整 preflight report。区分 `config_valid`、`environment_ready`、`implementation_ready`、`execution_enabled`、`authorization_ready`；prepare/doctor 可以检查禁用配置，live 前仍要求所有执行门。不能为让 preflight 绿而自动启用配置。

### P1-E：外部命令缺超时与缺失处理

`execution/sample_preflight.py:_default_runner` 调用 subprocess.run 没有 timeout，也未捕获 FileNotFoundError。Docker daemon 卡住可能表现为“启动无响应”；docker/git 不存在可能直接 traceback，而不是完整检查报告。

建议：每个检查设置有限 timeout，另有总检查期限；区分 executable_missing、permission_denied、daemon_unreachable、command_timeout、image_missing。某项失败后继续独立检查，依赖项标 blocked。持久日志只存脱敏必要字段。

### P1-F：shell 入口路径与配置格式问题

`run_safeclaw_sample_collection.sh`：

- 总是拼接 `${PROJECT_ROOT}/${CONFIG}`，绝对配置路径会被错误处理；
- 使用 json.loads 解析 `.yaml` 文件，当前文件恰好是 JSON，但真正 YAML 会失败；
- 正式 cd 到项目根发生较晚，前面的 Python 配置载入可能从外部 cwd 执行；
- run-id 正则允许 `.` 和 `..`，没有明确拒绝路径特殊段；
- pipeline_id 仍保留模板值，虽然 output_root 唯一，但需核查 batch/ledger identity 是否一致隔离；
- `--print-output-dir` 会先创建目录和派生配置，并非纯查询；
- `.env` 通过 shell source 在 help 前执行，Python CLI 和 shell 的加载方式可能不一致。

前两项可直接从代码确认；cwd 和 batch 的实际影响需补回归，不应在没有运行证据时断言已造成某次事故。

建议：把配置解析、路径规范化与派生放到公共 Python helper，shell 薄封装。支持绝对/相对路径，明确相对基准，统一 YAML/JSON loader；拒绝特殊 run-id 和路径逃逸。help/print/doctor 不执行实验、不覆盖配置。环境变量加载统一，禁止输出值或执行 dotenv 中的命令文本；保留明确的环境覆盖优先级。

### P1-G：单请求兼容性模板不能同时当完整链准入模板

`provider_compatibility_revalidation.disabled.json` 只给每角色1次请求、1个 Attacker decision，却配置两轮/两会话与持久化目标。Victim 一次工具调用往往需要后续模型请求才能完整返回。其有限预算适合有界协议观测，不保证完整 construction 或 accepted 样本。

建议：将 `compatibility_probe` 与 `single_trajectory_validation`、`benign_pilot` 的成功标准分开。Probe 按预注册协议检查判定；预算内正确触发 guard 可单列，而非声称完整任务成功，也不因缺 accepted 就认定 endpoint 不可用。不要自动提高请求上限，应先编译/估算目标所需阶段和预算并输出警告。

### P1-H：旧 pilot 预算与历史已知消耗不匹配

canonical pilot 仍设 `max_tokens=24000`。历史进度记录曾在单 action 后累计45326 Victim tokens 触发 guard；这说明旧默认预算至少对那些任务不够，不代表所有未来任务都需要同样额度。

建议：正常模式按小规模已授权开发校准确定预算，输出实际角色消耗、guard时机、预算范围。保留请求上限与墙钟硬边界；不要默认无限增加。token guard 是 action 后检查，不能声称请求前硬上限。

### P2-I：formal 缺 frozen library / v3 支持是后续阻塞，不是采集阻塞

本地 `data/primitive_libraries/frozen/safeclaw-main` 不存在；formal 仍只接受 legacy_chain_v2。正常库、v3 Planner/formal 未实现时应拒绝正式执行。

建议：仅把这些列为 formal readiness；不得要求先有正式 frozen library 才允许正常采集 pilot。依赖图不能形成“先有库才能采集、先采集才能有库”的环。

## 3. 历史错误归因：不要沿用已经过时的故障

| 类别 | 已有证据 | 当前能否据此断言仍失败 |
|---|---|---|
| Attacker HTTP502 | 20260915-101633 run 在第二次请求失败，已计费/计数 | 不能；后续两条summary已complete |
| token/turn预算 | 历史24k、256k批次分别预算中断 | 配置风险仍在，是否触发需新运行证明 |
| embedding transport | 历史存在，之后有修复通过记录 | 不可继续当未解决根因 |
| 跨会话证据缺失 | 214932 run admission明确失败 | 是该历史run事实，不可补造历史证据 |
| socket PermissionError | 多次出现在本机fake HTTP测试沙箱 | 不能等同真实provider不可达或配额耗尽 |
| 新benign live缺实现 | 当前CLI与实现只支持fixture | 当前本地确定阻塞 |

当前没有重新检查服务器 Docker daemon、image、网络、模型endpoint、凭证有效性。docker CLI 本地存在不证明 daemon 可用。真实在线状态未知，应通过服务器只读 doctor 与另行授权的最小 probe 分别核验。

## 4. 统一诊断与状态模型建议

新增离线优先的 `doctor`/`readiness`，输入 config 和可选 run-root、workflow-kind。名称可按项目风格决定。

输出必须包含：

```text
inspected_head / source_hash / config_hash / interpreter
workflow_kind: fixture | compatibility_probe | benign_collection | legacy_attack_collection | formal
implementation_ready / config_valid / environment_ready
execution_enabled / authorization_state
existing_run_state / launch_reservation_state
failed_checks / pending_checks / blocked_checks
first_actionable_blocker / all_independent_blockers
can_prepare / can_collect / can_analyze / can_evaluate
recommended_next_command (不得自动启用或自动真实运行)
```

分开两个命令模式：

- `doctor --offline`：配置/schema/依赖/文件/版本/现有产物检查，不使用模型、不启动容器；可以执行有界只读 docker info/image inspect，但需在说明中明确。
- `probe --live`：明确网络请求，需要独立授权和预算；不被 offline doctor 隐式调用。

退出码采用项目现有规范并版本化说明：执行异常、阶段未满足、等待审核、正常完成分开；不能更改退出码而不更新脚本/测试。JSON细节是事实来源，终端显示简洁中文解释和文件路径。

缺实现应直接给 implementation_missing，不能指导用户改enabled、删除marker或一直重跑。安全/科研门保留，但只阻止真正依赖它的阶段。

## 5. 给 Codex 的实施任务

先读 AGENTS.md、本文件和 `正常交互传播链驱动安全评测_研究设计与代码改造方案.md`。按服务器实际源码逐项复核；已修复项用测试证明，不重复重写。

### 第一批：诊断与入口可靠性（先完成）

1. 实现统一 doctor/readiness 及 workflow-kind；明确 benign live 是否实现。
2. 保存完整 preflight report，修复笼统异常丢失check原因。
3. 为所有外部检查添加超时、缺命令/权限/daemon分类；不输出凭证。
4. 修复绝对路径、外部cwd、YAML/JSON、特殊run-id；统一dotenv解析；shell只做薄封装。
5. 明确disabled准备和live执行两种门，不自动开启。
6. 为 compatibility probe 设置独立验收，不用accepted或跨会话强门评价单请求协议测试。
7. 汇总旧run时分离complete与admission_failed，不更改旧产物。
8. 文档、README、Makefile入口标明legacy/benign/fixture/formal；不要让默认示例误启动旧攻击采集。

### 第二批：新正常 pilot 的必要实现

若服务器同样缺失 benign live：

1. 新增合作式policy与SafeClaw正常任务mapping，复用现有真实driver/relay。
2. 增加独立的benign collect入口，严格禁止adversarial config混入。
3. 使用任务合法完成、观测完整性和planning-reference资格；跨会话只约束声明该能力的样本。
4. 不依赖尚不存在的formal库、不要求完成强干预profile才允许采集。
5. 保留每角色预算、墙钟、fail-closed、唯一run/batch、原子launch和所有权收尾。
6. 用本地fake gateway进行真实代码链集成，不能用fixture直接返回预制成功来称live adapter已验证。
7. 正常采集结果标记origin及真实/合成模式；真实网络与官方结果仍未验证。

这两批均只做代码与离线/fake验证。用户之后另行授权真实兼容性probe/benign pilot。不要在修复完成后自动运行。

## 6. 必要回归测试

- benign live未实现时明确报错，无请求；已实现时默认disabled。
- disabled config的环境检查可完成，但启动仍拒绝。
- preflight多个失败完整落盘，live摘要指向具体report。
- docker/git缺失、权限拒绝、超时、image缺失各有reason code。
- repo外cwd、绝对config、普通YAML、路径空格正常；`.`/`..` run-id拒绝。
- help/print无模型请求、无配置覆盖；dotenv恶意命令不执行。
- 多run输出、batch、ledger identity一致隔离；并发launch只允许一次。
- compatibility probe只有一次请求时不要求完整工具闭环accepted；不重复发起补救请求。
- 完成运行但profile未满足仍显示execution completed；runtime pending不变成API故障。
- frozen library缺失只阻止formal，不阻止已实现且获准的benign采集。
- 正常单会话不被强制跨会话；声明跨会话但缺read-from不误通过。
- provider 502、timeout、预算耗尽、schema错误分别归类，不通过无限重试制造通过。

执行专项后运行适当完整质量门，记录实际解释器与结果。修改bridge时补显式lint/import；schema变化再生成。环境限制单独报告。交付修改文件、doctor示例输出、可复现命令、当前第一阻塞、仍待真实证据项。不要只说“313个测试全绿，所以pilot可运行”。

## 7. 本轮未做的操作

未修改执行代码、配置或历史run；未读取凭证内容；未启动真实实验；未验证服务器在线环境。本文件中的潜在风险均应以针对性回归确认后修复，不能当作每一次历史失败的已证实根因。
