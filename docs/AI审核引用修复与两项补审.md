# AI审核引用修复与两项补审准备

## 目标与边界

直接实施局部修复及离线验证，不重做审核Agent，不运行真实请求。先读AGENTS.md、SECURITY.md、进度/计划顶部，核对git status和最近提交，保护所有未提交实现。优先阅读capability/ai_review.py、review.py、models/openai_compatible.py、12_m2_ai_review.sh和相关测试。

历史v5 `experiments/runs/capability/m2-ai-review-prepared-20260923-a29903a-v5/` 已terminal，8次HTTP均200、6个有效refuted、2个annotation_error。保持只读，不resume、不改账本、不补造丢失的响应。

仅准备以下两项的新审核批次：
- review-ad36e087ccd88d2c1838：历史missing pointer。
- review-b38c275bf56a1e515792：历史duplicate pointer。

使用OPENAI_BASE_URL、OPENAI_API_KEY、gpt-5.6-sol。新增最多2次Annotation HTTP，每项1次、零重试/修复请求、并发1，其他角色0；timeout120秒、batch600秒、输出参数上限4096，现金不声称硬限额。配置execution_enabled=false，本任务不创造真实调用授权。用户终端执行长测试/真实审核，你准备命令并查收；不要自行调用或反复申请审批。

## 1. 宿主生成可引用证据清单

不要只改prompt提醒模型。对每个真实case确定性生成允许引用的RFC6901 pointer清单，提供给模型原样选择；清单优先涵盖可见响应、写入参数、实际状态及必要的规则/材料字段，不把一个材料句子本身当成采用证明。

正确处理嵌套对象、数组索引、~和/转义，拒绝非法转义、越界/负数/非规范索引，不把JSON字符串内部假装对象展开。按固定顺序输出并绑定case hash、清单hash和版本。列表过大时显式限制/报错，不静默截断关键证据。可带简短有界预览，case仍是唯一证据来源。

输出schema可在实际客户端兼容时使用pointer enum及uniqueItems，但宿主必须独立校验：pointer在白名单、真实存在、不可重复、quote确实来自目标字符串、review_id匹配。uniqueItems不能代替按pointer去重，因为同pointer不同quote仍应被拒绝。不要自动删除重复引用或猜测修正不存在的路径来挽救标签。

## 2. 新版本prompt

保留v1文件或其已封存快照，新增明确版本的prompt（例如v1.1），只强化输出引用合同，不改变observed/refuted/unknown研究定义。规定复制allowed evidence pointers中的完整值、每pointer最多一次、解释引用与标签的联系。输出unknown不免除格式/引用校验，也不能把解析错误改成语义unknown。

不向模型发送旧六项标签、旧AI草稿、失败项应为refuted的暗示或研究者条件映射。每case独立上下文，不要求私有思维链。prompt/hash/schema/清单版本绑定新run。

## 3. 校验前留存最小响应证据

沿用已有provider返回及脱敏设施，在语义解析/引用校验前保存模型输出的受控证据，使无效JSON也可诊断。核对客户端当前接口，必要时最小扩展，不打断其他调用者。

保存内容仅限已审查synthetic审核响应所需字段，不保存Authorization、API key、全部环境或任意response headers。先secret scan/redaction，0700目录/0600文件、明确大小上限；记录是否截断/脱敏、保存表示的hash范围、attempt/status/model/finish/usage可观测信息。不能宣称脱敏副本是逐字原始响应；疑似秘密不写原文或低熵秘密hash，fail-closed并留下非敏感错误。

响应已收到但证据写入失败时仍计请求，标记evidence_persistence_error，不能报0或再请求。错误记录引用已保存响应与校验reason，原模型输出和未来人工/确定性修正必须分开。历史缺失响应无法恢复，不用当前AI猜测补回。

## 4. 两项子集与跨版本汇总

配置/prepare支持显式review ID子集，校验非空、唯一、属于原包，冻结原case hash。无需把原八项表改成两项或重新导出条件数据。新run保留原包分母8及本批请求分母2，防止只算有效结果。

若现有导入要求全量8项，不放宽成任意缺项。提供显式派生合并：验证同一manifest/case/rubric与AI来源，保留v5六项有效标签，新run只提供两个指定case；冲突、未知ID、输入变化拒绝或显式disputed，不按想要的结论选择版本。保留旧错误及总计尝试记录。

汇总每项来源run、model、prompt版本/hash、case hash、响应/校验引用、有效/错误状态。新两项成功后可显示8/8有效覆盖，但必须标mixed_prompt_versions，不称单一新版八项评估、准确率或独立人工完成。补审失败继续保留annotation_error/未标注unknown，禁止再自动申请第三次。

## 5. 回归与交付

先写失败反例再实现：missing/duplicate pointer、同pointer不同quote、~0/~1、非法数组索引、JSON字符串伪路径、quote错配、清单/case篡改、无效JSON可追溯、响应过大/含secret、证据写失败后仍计attempt、terminal不能重跑、两项限制、跨版本合并冲突、AI标签不计human。

短时纯测试自行完成；本机HTTP及完整质量门给用户准确命令，遵循用户偏好，不用历史422 passed作本轮结论。至少离线fake走请求构造→响应留存→校验→错误或标签→来源报告。无需Docker或再建大矩阵。

更新已有12脚本支持配置/子集准备及必要合并入口，保持薄封装。所有修复稳定后只prepare一个新的禁用两项候选，validate/dry-run零请求；不要自动bind/run。给用户具体模型、预算、唯一路径、指纹和真实执行前的授权范围，再由用户终端运行。

开始更新WORKPLAN，每个独立步骤保存PROGRESS。两项补审不是M3离线准备的前置门，不无限拖延主线；本轮仍只做审核修复，不同时展开M3实现。原harm/constraint/primitive/official结论不变，不commit/push/reset/clean，不修改历史封存证据。
