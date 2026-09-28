# 使用本地科研 Skills 整理当前代码的任务 Prompt

请直接审查并整理本项目当前代码，目标是提高结构清晰度、科研判定正确性、可测试性和复现性，不是扩大实验范围。本轮不替代现行 R4 功能开发；先确认其他任务已停止修改同一文件，再建立基线并开始。

## 使用已安装的两组 skills

本地位置：`/home/scarramcci/.codex/skills/`。这些是两个上游仓库提供的 skills，不是两个单独 skill；按需读取，不要通读全部118个文件。

第一组 research-paper-lifecycle-skills：
- `$refactor-research-code`：科研代码结构/发布审计，先执行其中只读 release_audit.py，并理解退出码和审计局限；
- `$test-research-code`：针对可复现实验入口、回归和环境记录，补缺失的有效测试。

第二组 uw-ssec/rse-plugins：
- `$hardening-research-code`：用独立规则和不变量核对正确性，不能把当前输出直接当正确答案；
- `$python-testing`、`$code-quality-tools`：按需改善测试分层、fixture、lint与类型检查；
- `$validating-implementations`：逐项核对本轮验收条件；
- `$ensuring-reproducibility`：记录并验证离线可复现路径；
- `$python-packaging`、`$scientific-documentation`：仅在包结构、依赖或文档确有问题时读取。

RSE 文档若引用 `ai-research-workflows:xxx` 或 `scientific-python-development:xxx`，本机是平铺安装，使用 `/home/scarramcci/.codex/skills/xxx/SKILL.md`。Claude 专用 agents/commands/hooks 未启用，不假装调用它们。

## 已明确的范围与执行方式

先读 AGENTS.md、SECURITY.md、进度和计划顶部，检查 git status/log，确认实际R4状态。用户没有要求匿名投稿/发表/上传：本轮 blind=none，不匿名化、不添加许可证、不创建论文材料或远程PR。

我授权你自行完成行为保持的结构整理、imports修复、文档更新、类型改善、重复纯逻辑提取和必要回归测试，不需要再就每个低风险修改确认。skill中普通审计/计划先行可直接做，随后实施这些已授权项目。

可能改变研究含义的事项不得混入清理：判分公式、unknown准入、split/曝光、检索policy、种子/顺序/预算/模型、攻击面/权限/网络门。发现错误先用最小反例证实，记录建议与影响，继续其他已授权工作；实施此类研究行为变化前集中询问一次，并说明来自哪条skill或项目边界。

不要继续盲删代码。确认为重复实现且依赖和行为测试支持的提取可做；仍有用户或runtime用途的分支不能因“看似旧”删除。不要恢复整套已删除旧路线。

## 实际整理顺序

1. 建立当前可运行基线：读当前合同、CLI、脚本、核心测试。识别R1/R2/R3/R4边界及正在开发的文件。记录现有失败，区别环境限制与断言失败。
2. 运行所选skills提供的只读审计，先检查脚本内容与参数。只审查当前src/scripts/configs/tests/必要文档，排除历史experiments/runs、data、pinned upstream、.git、缓存和凭证，避免将私有历史内容写入报告。工具不支持排除时用受控路径和文件上限，不改项目证据。
3. 检查职责：纯合同/判分、观测映射、候选/库、Planner、runtime/provider、CLI/report是否分明；仅在有清晰职责和测试支持时拆分，不按文件长度机械拆包，不新增万能框架。
4. 检查source=fixture/local_fake/real、事件身份、request/result/commit、schema版本、异常处理、HTTP失败计数、原子输出、重复启动、secret scan、private/public视图。输出保持不变只证明回归一致，不代表判定正确；同时写不变量/反例。
5. 保持no_library/raw/structured实验定义和相同样本配对，不把预设fixture当实际Victim结果；依赖判分/evaluator与private oracle不进入模型公开输入。
6. 清理硬编码路径时优先保持当前默认行为与工作目录语义。不要主动迁移conda到pixi/uv、Hatchling，不为使用skill而更换现有工具链。
7. 将测试区分纯离线、loopback HTTP、Docker生产链、真实实验；默认质量门绝不触发真实请求。CI依赖历史绝对运行目录的问题要用明确隔离fixture解决，仍保留相关语义拒绝反例，不删断言制造通过。
8. 统一编号脚本帮助、参数、退出码、唯一输出和错误提示。文档告诉用户该步做什么、是否需Docker/真实请求、产物在哪里，不只列一堆内部门槛。

## 验证与证据保护

先受影响测试，再适当make check、定向schema生成、Bash syntax、git diff --check。已有环境优先使用；需要联网安装依赖或改变环境时先列明，不能偷偷升级全套依赖。

记录新鲜输出，不能照抄旧测试数。耗时Docker/fake命令交我终端执行，查收产物后标“用户执行、助手复核”；不得因为skill要求亲自重跑而重复真实或长时实验。

本轮只验证可控离线重放/工程可复现性。不能宣称真实模型输出确定可复现；没有清洁环境复验就注明未完成，不以环境文件存在代替复验。

重构造成source指纹变化时，历史bundle/lock/library保持只读，记录版本兼容边界，生成新工程产物。不要为让旧产物通过而更新封存hash或关闭校验。

## 交付

- 直接完成已授权整理，不只给建议。
- 更新进度/计划顶部和相关结构/运行文档，不另建相互冲突的长期计划。skill要求的审计/验证报告作为有证据的附件，由进度链接即可。
- 汇总实际改动、行为保持依据、真实测试及失败、待批准的研究语义问题、后续R4工作，避免空泛“全面优化”。
- 本轮无真实模型/API/付费探针/bind/live/正式冻结授权；不commit/push/reset/clean，不清理未知进程、容器或历史证据。
