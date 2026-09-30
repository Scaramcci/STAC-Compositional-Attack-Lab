# R4 live-readiness 实施与待验收

基线 HEAD `d71a8b8`，保护起始用户文档修改。执行源码及 fake 脚本指纹见 [源码基线](r4-live-readiness-20260928-source-baseline.json)。历史运行、raw、账本、封存 hash 未修改；真实 bind/模型/API/live 均未执行，真实请求 0。

## 实现

- `r4_batch.py`：prepared `/2` 全字段严格校验；prepare/validate/seal/replay 共用 `r4-execution-dependencies/2` 的 32 个必需执行依赖，不锁本仓库一般文档。校验 task/group/split/candidate/materialization/pinned/image、五角色集合/上限、model 与完整规范化 endpoint/API 身份，拒绝 userinfo/query/fragment/歧义路径和未知版本。旧 prepared/case 只读，不迁移授权或改 hash。
- 生命周期：`prepare_disabled`→`validate_prepared`→`bind_disabled`→`activate`→`run_disabled`→terminal→review/replay。函数旧名称保留入口兼容，bind/run 已实现。每次 prepare 冻结唯一 run UUID，即使目录末级同名也不复用授权/执行身份。manifest 始终 disabled/unbound；实际 binding、activation、runtime claim、terminal 是独立排他/fsync 记录。
- 授权记录：`attack-r4-authorization/1` JSON 含 schema/scope/manifest_hash/text；text 必须对应 `r4-authorization-preview` 的精确批次原文。bind/run 需同一原文文件与真实 SHA256、显式旗标；文件存在/hash 不证明授权真实性，binding 明确记录操作员 attestation。fake 记录与旗标仅用于固定本机 fake，不可用于 real。
- 真实 API 和 CLI 路径验证 binding/config/source 指纹及期限，执行配置完全来自冻结快照，拒绝直接传 endpoint/key/budget 绕过。凭证只在真实授权执行时从指定环境读取。绑定有效期从 bind 开始；episode 期限从原子 activate 开始，并被绑定绝对有效期截断。重复/concurrent launch、terminal、expired、已 claim 的执行拒绝重新发送。
- `r4_runtime.py`：同一真实 adapter、受控 relay、双 session、状态/官方检查和 sealed case。由固定 image digest 启动 owned 容器；断网只读检查发现 OpenAI SDK 默认重试 2 次、Pi agent 默认自动重试最多 3 次，新增只在 owned 容器内、核验原文件 SHA256 后关闭重试的覆盖与 before/after 证据，不改 upstream 或镜像。失败/不确定发送照计，缺账本计数 unknown；证据未完整归档时保留 ledger volume。
- `provider_relay.py`：deadline/model 门、持久 duplicate 请求拒绝、零重定向，复用原预扣账本。账本文件缺失/损坏拒绝读取与重启，不把缺失当空账本；清理独立保留 120 秒，只作用于本批资源。归档前先通过认证控制入口持久 freeze 新 provider 发送；`runtime-evidence.json` 原始数据 fsync 成功才可删除 ledger volume。磁盘/捕获/freeze 失败保留 volume；内存捕获不当作归档，绑定路径强制固定证据输出目录。
- `r4_fake_provider.py`：实际 search→`sim-google gmail get <已核验唯一文件名> --json`→由工具正文构造 write→第二 session synthetic .env 读取。配置不注入邮件 payload 到模型上下文，不新增镜像路径，不读实际 provider 凭证。
- `r4.py`/事件合同：分列预置、请求、摘要、完整/部分结果、provider 上下文可达、实际提交。完整正文按 pinned sim-google parser 去除两端空白；原 eml hash 作为内容版本。来源 claim 关联 transcript 调用/结果、资源/范围、provider 返回调用参数、同 session 后续 provider 请求中的工具结果引用和实际 session 关闭记录。semantic consumption/causal contribution 保持 unknown；官方判分和最终危害不强制依赖来源 claim。real seal/replay 还需原批 binding/activation/claim 记录一起保留。

## 实际验证

最小失败反例：初始 manifest/lifecycle 11 failed、3 passed；字符串匹配来源 4 failed；未知来源版本 1 failed；retry overlay 接口缺失 1 failed；relay 跟随 302 重定向 1 failed；同名新父目录授权身份碰撞 1 failed；先 durable archive 再清理/磁盘失败 2 failed；freeze 控制入口 1 failed。随后修复并执行专项。

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 /home/scarramcci/miniconda3/envs/stac/bin/python -m pytest -q tests/integration/test_attack_program_r3_semantics.py tests/integration/test_attack_program_r3_http.py tests/integration/test_attack_program_r4_semantics.py tests/integration/test_attack_program_r4_http.py tests/integration/test_attack_program_r4_lifecycle.py tests/integration/test_attack_program_r4_source.py
make lint typecheck PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python
make check PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python
make schemas PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python
bash -n scripts/attack_program/15_r4_fake_check.sh scripts/attack_program/14_r4_control.sh scripts/attack_program/13_r4_prepare.sh
git diff --check
```

合并专项 **69 passed in 40.85s**；run 身份修补后完整门 **105 passed in 97.36s**；最后 archive/freeze runtime+HTTP 专项 **20 passed in 9.79s**。**最终源码完整 `make check`：Ruff format/check、mypy 24 源文件通过，pytest 107 passed in 105.38s。** Schema 审查：新增 prepared 合同，run UUID 有格式约束且必填；事件新增五类非语义消费记录，并同步 observation/development 嵌入合同；bundle 新增材料、runtime 控制与 binding 指纹，未删除已有合同字段。Bash syntax、`git diff --check` 通过，源码基线 32 依赖与 fake 脚本全部匹配。

额外实际检查：`docker image inspect openclaw-env:2026.3.12 --format '{{.Id}}'` 和断网临时容器只读检查 image 内 SDK/agent 源码；两处 retry overlay 各恰好一次替换并通过原 SHA256 验证。image `sha256:e08c04ebf0dcc0015f27c96bb9adaad4fd1032cbbcfa73a3b9f5114eed862357`。这些检查没有模型请求，不等于新版 Docker/fake 验收。

## 用户唯一新运行

本次目录及外部 audit 目录未存在，执行：

```bash
STAC_PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python bash scripts/attack_program/15_r4_fake_check.sh r4-fake-live-readiness-20260928-v1
```

脚本走新版 prepare/fake-bind/run 共享入口、实际 OpenClaw/relay/tool/state/seal，正常、完整邮件读取后合成写入、拒绝工具三案；然后 CLI 独立 replay。退出码自动存入 `experiments/runs/attack-program/r4-fake-live-readiness-20260928-v1-exit-code.txt`。查收命令：

```bash
cat experiments/runs/attack-program/r4-fake-live-readiness-20260928-v1-exit-code.txt
STAC_PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python bash scripts/attack_program/14_r4_control.sh r4-status --batch experiments/runs/attack-program/r4-fake-live-readiness-20260928-v1/prepared/r4-dev-one
```

助手收到回传后只读查 `report.json`、三份 binding/activation/terminal、`execution/runtime-evidence.json`、`prepared/<id>/execution/case/` 的 bundle/observation/result、外部 audit 和 partial/cleanup；核对全部尝试分母与邮件来源，并在另一个新目录 replay。不覆盖脚本已有 audit，不自动重跑失败或历史运行。

## 唯一真实候选与授权缺口

新版 fake 尚未查收，真实候选尚未创建，不称 ready。计划唯一新目录 `experiments/runs/attack-program/r4-real-dev-disabled-live-readiness-20260928-v1/`（当前未存在），任务 `pse-2.1-001`、文件候选 `r4-dev-one`，只在上述 fake 查收后重新 prepare/validate。当前非敏感配置读取为 model `ep-20260909180104-hmx9m`、endpoint `https://ark.cn-beijing.volces.com/api/v3`；最终准备时仍须重新核对，不能把旧候选配置/授权作为本批批准。

待核对预算：Victim 最多 12 HTTP；Attacker/Planner/Annotation/Embedding=0；零 retry/fallback；请求 90 秒、session 360 秒、激活后 episode 900 秒、bind 后有效期 3600 秒、cleanup 120 秒、输出参数 1024 tokens。只有 HTTP/时间硬上限，成本 estimate-only；不是总 token 或金额硬限制，也不能保证真实任务足够完成。

fake 查收后准备该唯一禁用候选，交最终 manifest/source/config/material 指纹、可复制批准原文与绑定/运行命令预览；本轮不生成真实审批记录或保存真实授权 hash。实际真实 bind/请求/live 仍缺覆盖该新批的用户明确授权。held-out 审计属于后续正式三臂阶段，不阻塞此 development 准备。
