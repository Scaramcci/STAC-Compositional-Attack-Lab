# 代码整理与验证记录（2026-09-28）

## 范围和基线

- 依据 [整理任务](SKILL_BASED_CODE_REVIEW_TASK.md)；blind=none。检查开始时 HEAD 为 `7f4e27c80ee391cbffcd08ad3da16f3819b12100`，工作树已有未提交 R4 源码、schema、脚本和文档。本轮未改历史 `experiments/runs/`、`data/` 或 pinned upstream。
- 使用 `refactor-research-code` 的只读 `release_audit.py` 分别扫描 `src/stac_attack_lab/attack_program`（16 个源码文件）、`scripts/attack_program`（13 个）和 `tests/integration`（7 个），参数 `--blind none --max-files 80/30/20 --max-bytes 500000/200000/500000`；退出码均为 1，分别报 68/2/8 个 ASK-FIRST。脚本是启发式静态扫描，退出码 1 表示需人工判断，不表示测试失败。子目录扫描产生“缺 README/LICENSE/.gitignore/入口/配置”假阳性；仓库根目录已有 README、`.gitignore`、`pyproject.toml` 和 CLI/Makefile。缓存命中不授权删除工作树文件。
- `test-research-code` 的只读 `repro_check.py src/stac_attack_lab/attack_program --max-files 80` 退出码 1；其五项 MISSING 主要来自只看子目录。真实缺口是根目录 `pyproject.toml` 只有依赖下界、没有锁定环境；本次不迁移包管理器或声称完成清洁环境复验。
- 修改前专项集成链：`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 /home/scarramcci/miniconda3/envs/stac/bin/python -m pytest -q tests/integration/test_attack_program_pipeline.py tests/integration/test_attack_program_r2.py tests/integration/test_attack_program_r3.py tests/integration/test_attack_program_r3_http.py tests/integration/test_attack_program_r3_semantics.py tests/integration/test_attack_program_r4_http.py tests/integration/test_attack_program_r4_semantics.py`，59 passed in 69.25s。此数只是修改前基线。

## 已实施

- 提取 `file_io.write_json_exclusive`，让 CLI、R2/R3 与 R4 共用排他创建、JSON 编码和私有权限路径；R4 仍使用排序键、flush 和 fsync，其他调用保持原有格式。R3 改为直接依赖该文件模块。
- 新增从 CLI catalog 到 R4 launch 的集成回归，检查公开 JSON 可读、私有文件权限、原有字节格式和重复启动拒绝。将新模块加入新 R2/R3/R4 产物的处理源码指纹。
- 更新 README、结构和脚本导航。R4 Docker fake 已由前一任务的用户运行与独立查收；本轮未重跑 Docker、未执行真实模型/API、bind、live 或正式实验。

## 独立判据与边界

- 文件层不变量：既有路径不得覆盖；私有 launch 不授予组/其他用户权限；R4 封存写入需落盘同步。新增测试检查前两项，R4 fsync 保持原调用参数并由代码审查确认；现有 R4 replay 测试检查封存语义与篡改拒绝。
- 已有语义反例覆盖错误 session、重复 call/result、unknown 工具、篡改重算 hash、缺失官方状态、清理异常、预算预扣和网络隔离。它们是独立不变量的回归证据，不把现有输出升级为真实攻击正确性证明。
- 发现但未改研究语义：R4 fake 攻击案缺 `source_delivered`，严格要求可归因邮件读取会使“模型消费该材料”的结论保持 unknown，并可能影响库准入；当前 split 无独立 held-out test 组，重分组会改变样本分母与三臂可比性；真实候选仅有 Victim 12 次 HTTP/时间上限、无硬金额上限，新增金额门会改变停止条件和尝试分母。上述变更需具体研究决策与反例，不能混入结构整理。
- 静态审阅还发现 `r4_batch.validate_prepared` 逐项验证 manifest 自报的 `processing_source_hashes`，但不核对必需文件集合。待运行的最小反例是：复制当前禁用候选到临时目录，移除其中一个源码键并重算未签名的 `manifest_hash`，检查 `r4-validate` 是否仍返回 `valid_disabled`。若成立，未来 bind 仅依赖该校验会遗漏被删文件的源码版本；补必需集合检查会拒绝这类旧/手改 manifest，需新批次产物和语义授权。当前 `bind`/live 固定拒绝，未把此静态发现说成已实测绕过。
- 新源码指纹与旧封存 manifest 不兼容。旧 R4 fake case 和禁用候选对应原源码版本；不能为通过新校验而重写它们。新工程产物必须使用唯一目录生成。哈希一致只说明完整性，不证明来源消费或因果。

## 验证与复现

- Python 3.11.16，HEAD 如上，工作树 dirty；输入为仓库 pinned SafeClawArena task/judge/patch、当前配置与 synthetic fixture。R3 配置显式记录 seed（默认 17），但本机 fake runtime 的 UUID/时间身份和真实模型输出不保证逐字节重现。静态审计的“无 seed”是其只识别 RNG 设置调用的局限，不能据此改动 R3 顺序。
- 修改后先运行 R4 语义/HTTP 与新文件回归 18 passed in 2.39s、R3 语义/HTTP 与新文件回归 9 passed in 10.13s。增加源码指纹后再次运行 `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 /home/scarramcci/miniconda3/envs/stac/bin/python -m pytest -q tests/integration/test_attack_program_file_io.py tests/integration/test_attack_program_r3_semantics.py tests/integration/test_attack_program_r3_http.py tests/integration/test_attack_program_r4_semantics.py tests/integration/test_attack_program_r4_http.py`：26 passed in 12.71s；`make lint typecheck PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python` 通过（Ruff，mypy 24 个源文件）；`bash -n scripts/attack_program/*.sh` 和 `git diff --check` 通过。
- 新当前源码禁用候选：以下两步均退出 0；验证为 `valid_disabled`，Attacker 0/Victim 最多 12 HTTP，manifest 包含新模块指纹，`execution_enabled=false`、`binding=null`。两步只作本地 preflight/校验，无真实模型请求。

  ```bash
  STAC_PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python bash scripts/attack_program/13_r4_prepare.sh --candidate configs/attack_program/r4_development_candidate.json --output experiments/runs/attack-program/r4-real-dev-disabled-code-review-20260928-v1
  STAC_PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python bash scripts/attack_program/14_r4_control.sh r4-validate --batch experiments/runs/attack-program/r4-real-dev-disabled-code-review-20260928-v1
  ```
- 完整 `make check` 和新 R2 synthetic 工程产物命令已交用户终端执行，结果待查收；本轮没有清洁环境复验，故只称“当前环境离线可运行”，不称跨环境可复现。R4 Docker 长链沿用前一检查点的用户执行、助手查收证据，不能替代新源码版本的长链验收。

## 验收结论

已完成行为保持的共享写入整理与运行导航更新；短时验证支持现有入口与封存拒绝语义，新 R4 禁用候选已校验。全量修改后测试、新 R2 工程产物和清洁环境复验尚待查收。真实研究 claim、held-out 结构、预算及安全门均未在本轮改变。
