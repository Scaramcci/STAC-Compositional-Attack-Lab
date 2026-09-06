# SafeClaw Integration

本目录包含：

- `construction_bridge.py`：collection 阶段连接 Construction Attacker 与 OpenClaw Victim；
- `formal_bridge.py`：formal 阶段执行逐 stage Attacker action；
- `patches/a11f5cce-safety.patch`：在临时 upstream 副本上移除敏感输出并注入受控模型配置。

外部 checkout 路径为 `upstream/SafeClawArena`，固定 commit 为 `a11f5cceaba0676be721021f8d232638fd111305`。该目录被 Git 忽略，必须由操作者准备。Preflight 不会自动下载、更新或修改 upstream。

Patch 只应用于临时副本。Materializer 只能修改 task set 允许的 JSON pointer；official evaluation、private oracle 和凭证不得进入模型输入。

## 方舟多模态 embedding

当前 pilot、main 和 environment 配置使用 `embedding_provider: ark_multimodal`。
`.env` 中填写：

```dotenv
SAFECLAW_EMBEDDING_MODEL=ep-your-ark-endpoint
SAFECLAW_EMBEDDING_BASE_URL=https://ark.cn-beijing.volces.com/api/v3
SAFECLAW_EMBEDDING_API_KEY=your-ark-api-key
```

接入点必须支持 `/embeddings/multimodal` 的纯文本输入。实验启动时，runner
把标准库适配器源码和配置通过 stdin 注入临时 Victim 容器；适配器只监听容器内
`127.0.0.1:18792`，随容器退出，无须安装方舟 SDK、下载模型或开放宿主机端口。
配置文件权限为 0600，启动参数不包含密钥，适配器不会记录输入或上游错误正文。

OpenClaw 继续使用 `openai` memorySearch provider。适配器将 `/v1/embeddings`
中的每条文本分别发送到方舟，转换 `data.embedding` 为 OpenAI 的 `data[]`，
保留输入顺序，支持 float 和 base64 编码。不能直接将多个文档放进方舟的同一个
多模态 input 数组，否则得到的是融合向量。远程异步 batch 功能关闭；任一条失败
则整次请求失败，不返回部分向量。dimensions 覆盖和 token ID 输入不支持。

原有标准 OpenAI embedding 服务仍受支持：将上述三个版本化配置的
`embedding_provider` 改回 `openai`，并设置对应的模型、API 根地址和密钥。

聊天 API 独立配置。当前 Attacker/Planner 从 `OPENAI_BASE_URL`、`OPENAI_API_KEY`
读取配置，默认 Victim 也使用这两个变量。使用 Gemini 时须填官方兼容地址
`https://generativelanguage.googleapis.com/v1beta/openai/` 和 Gemini 密钥；仅添加
`GEMINI_API_KEY` 不会自动切换服务。`.env` 解析器不会展开 `${GEMINI_API_KEY}`。
宿主机的 Clash 代理测试通过也不代表 Docker 内的 OpenClaw 已配置代理；容器内的
127.0.0.1 指容器自身，真实实验还需另行验证容器访问聊天接口的网络路径。
