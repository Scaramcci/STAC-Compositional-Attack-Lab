# 下一轮 Codex Prompt：R4 绑定/执行接口与来源证据闭合

## 当前核对与范围

本轮直接实现，不只提建议。先读最新 AGENTS、SECURITY、PROGRESS/WORKPLAN 顶部、R4 runtime任务；检查git status/log，保护现有文档修改。审阅基线HEAD d71a8b8，实际开始时重新核对。

代码整理已完成，现有共享file_io、R1–R3工程链、R4 Docker/local-fake链保留。用户已运行fake三案并查收，记录10次本地HTTP、3/3清理。本次交接复跑R4 semantics：12 passed in 0.91s；没有重跑Docker/全库。历史60 passed是上一轮用户终端结果，不冒充本轮验证。

目前 `r4_batch.bind_disabled/run_disabled` 总是拒绝；`r4_runtime.execute_case(mode="real")` 也总是拒绝。禁用候选不是一个已可运行的真实入口。下一步完成这些接口的离线实现与fake验收，最后交付一个默认禁用真实候选。**本任务不授权实际真实请求或真实bind。** 不要以缺真实授权为由拒绝实现有授权校验的代码。

按需使用 hardening-research-code/python-testing 验证不变量，creating-handoffs写交接。不再对整个项目开展一轮通用重构；不恢复旧路线。

## A. 先修 manifest 校验完整性

当前validate_prepared仅遍历manifest提供的processing_source_hashes。先写反例：删除一个必需源码键、清空集合、增加越界路径，然后重算manifest_hash，仍必须拒绝。

建立显式、版本化且prepare/validate共用的执行依赖集合，覆盖实际影响物化、projector、判分、relay/HTTP预算、redaction、合同、配置与split/policy的文件；不要无差别锁整个仓库文档，否则无关文档变化又导致候选失效。

严格校验字段、必需键集合、预算上下界/角色集合、candidate/task/group/split/model/endpoint身份、材料hash、pinned来源与image；路径限定项目预期集合，不读取外部任意路径。未知schema拒绝。重算hash不能掩盖语义不一致。

endpoint不能只锁host：路径/API类型等会改变实际请求目的地，保存不含secret的规范化身份，拒绝userinfo/query凭证，执行时与配置一致。凭证仅从环境读取，不写manifest。

旧候选只读，新版本重新prepare；不能迁移旧授权或手改execution_enabled。

## B. 绑定与执行生命周期

实现prepare→validate→授权绑定→activate/run→terminal→review/replay：

- 冻结prepared manifest不变；独立binding记录授权原文引用/hash、manifest/config/source指纹、任务/角色/HTTP/时间上限与有效期。不把预览文案或占位符当授权，不把引用文件存在当授权真实性的自动证明。
- CLI真实bind/run需显式授权旗标与一致的授权记录；默认零请求拒绝。零请求preflight不发模型探针。
- bind开始的是授权有效期；episode执行期限在原子activate后开始，未激活的人工等待不消耗episode运行时长。记录两者，不重置过期时钟。
- 原子唯一launch、防并发与重复运行；结果存在或发送状态不确定时先status/reconcile，不自动重发。terminal未用额度不转给新任务。
- 真实执行配置完全来自校验后的快照。不能简单删掉mode=real拒绝行，留下直接传endpoint/budget绕过绑定的入口。API与CLI都验证执行上下文。
- 复用当前relay和HTTP持久账本；失败/不确定发送照计，零隐藏retry/fallback。核对pinned runtime内部重试配置，不能只控制外层。
- bounded cleanup独立保留必要收尾时间；上游异常仍封存partial证据和请求计数。只清理owned资源。
- status必须清晰显示disabled/prepared/bound/active/terminal/expired及可用下一动作，不抛FileNotFoundError要求用户猜流程。

开发测试中的授权使用显式fake上下文和本机endpoint；不能自动生成真实审批或把fake授权转成real。

## C. 补可归因的材料读取，不伪造语义消费

已知fake攻击案只有Gmail search摘要，无source_delivered，却继续写入。历史提交结果保持，但不能声称邮件完整进入模型。

先检查真实sim-google/tool接口，修改fake对话让它实际取得目标邮件完整内容，再给出写入动作。不能直接由harness把payload插进Victim上下文来冒充工具读取，也不能为方便随意增加镜像路径。

projector区分：材料预置、请求读取、摘要可见、完整/部分结果送达、后续provider请求上下文可达、实际提交、语义消费/因果贡献。完整内容送达需实际tool call/result、资源身份、内容版本或范围、provider边界引用。相同字符串/hash不能独自证明来源。

加入摘要-only、读取错邮件、空/截断/重复结果、完整内容无后续请求、越界读取等反例。仍不可观测时保留unknown；不要求Adopt为observed、不把最终危害强制依赖source_delivered。来源证据影响传播claim，不改写原始官方判分。

改fake协议不是证明真实模型一定会读；真实批次可能不读或不攻击成功，应保留这种结果。

## D. 同路径 fake 验收

先无Docker专项：manifest重算hash反例、角色/endpoint/预算错配、无授权零请求、过期、并发/重复launch、send后异常计数、partial清理与terminal拒绝。

再给一个用户终端命令，经过新版prepare/fake-bind/run入口、实际OpenClaw/relay/tool/state/bundle/replay，验证正常、完整材料读取后合成提交、拒绝/缺证据；不只重复调用旧run_local_fake_batch绕过新状态机。

所有fake明确local_fake，禁止读取实际provider凭证或连接真实服务。给唯一输出目录、退出码、查收命令。已有fake历史不重跑；新源码和新机制用新目录。若用户尚未回传，则报告“已实现、生产链待验收”，继续不依赖它的离线工作，不提前称ready。

## E. 首个真实开发候选（只准备、不绑定/执行）

新版fake查收后准备唯一新禁用批次。优先一个development任务pse-2.1-001与一个文件候选，Attacker/Planner/Annotation/Embedding=0，Victim上限/timeout由实际所需和已验证参数确定并列清，不继承旧余额；不必为了首个兼容性批次加模型生成器或三臂。

当前候选曾使用Victim 12 HTTP、90秒请求、360秒session、900秒episode、3600秒绑定有效期、1024输出token。它们是待核对背景，不是本次授权，不能保证足够完成任务。模型和完整endpoint身份从实际配置读取，缺失就明确缺口，不猜模型。

硬金额上限不是本轮必须另建的新框架：沿用HTTP/时间硬上限，明确cost estimate-only；不宣称token输出参数是总token或现金硬上限。仅用户明确要求现金硬限制时再设计。

不把held-out组审计设为首个development执行的前置条件。它属于正式三臂阶段，本轮记录尚缺即可。

提供可复制的完整授权文本与绑定/运行命令预览，绑定前核对最终指纹；本轮保持execution disabled/unbound/0真实请求。命令不能含容易被原样执行的AUTHORIZATION_REFERENCE占位符；用户实际授权后再保存原文与真实hash。

## 验证、文档与交付

实际跑受影响专项、适当make check、定向schema、Bash syntax、git diff --check；长时Docker/环境受限步骤交用户终端。保存最新源码基线，独立replay不得写历史bundle。

更新PROGRESS/WORKPLAN顶部、脚本运行说明；AGENTS首句R1–R3已过时，可精确改为“R1–R3离线主链及R4运行适配，本机fake已验证，真实执行按批次授权”，不能写成真实研究完成。

最终只说明：修复/新增文件、实际测试、还有哪些用户命令、唯一候选状态、真实请求0、真实授权缺口。不得commit/push/reset/clean，历史证据只读。

本轮结束标准：不是攻击必须成功，而是授权/执行门能实际工作，材料观测边界正确，默认关闭且有可审阅的首个真实开发批次。随后由用户单独授权执行，查收后再接模型生成探索与真实研究库，不重复旧M3。
