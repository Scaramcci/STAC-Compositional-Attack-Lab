# SafeClaw Integration

本目录包含：

- `construction_bridge.py`：collection 阶段连接 Construction Attacker 与 OpenClaw Victim；
- `formal_bridge.py`：formal 阶段执行逐 stage Attacker action；
- `patches/a11f5cce-safety.patch`：在临时 upstream 副本上移除敏感输出并注入受控模型配置。

外部 checkout 路径为 `upstream/SafeClawArena`，固定 commit 为 `a11f5cceaba0676be721021f8d232638fd111305`。该目录被 Git 忽略，必须由操作者准备。Preflight 不会自动下载、更新或修改 upstream。

Patch 只应用于临时副本。Materializer 只能修改 task set 允许的 JSON pointer；official evaluation、private oracle 和凭证不得进入模型输入。
