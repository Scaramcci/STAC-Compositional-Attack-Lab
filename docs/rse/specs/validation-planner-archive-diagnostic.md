# 拦截诊断离线验证（2026-10-01）

对应[实施记录](plan-planner-archive-diagnostic.md)。未发送真实请求、未启动Victim/Docker。

- 先最小反例：7 failed，包括空凭证归档反例、缺失类别/长度接口。
- 新扫描规则、两种长度、多规则、空凭证、正常计划，以及22单次diagnostic经生产HTTP客户端的loopback fixture通过。8种HTTP情形覆盖正常/精确key/凭证格式/赋值/CANARY/model limit/capture limit/仅HTTP额外字段敏感；实际各1请求，日志和summary没有测试秘密，拦截无候选，重复请求/B拒绝。
- 共享R3 HTTP/语义/主链及R4 generation连同新增专项：72 passed in 64.82s。随后补充无正文/脱敏不落入未执行invalid_plan回归并验证最终源码，受影响专项48 passed in 15.18s；两组有重叠，不相加。
- 最终专项命令：`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 /home/scarramcci/miniconda3/envs/stac/bin/python -m pytest -q tests/integration/test_planner_protection_diagnostics.py tests/integration/test_planner_failure_evidence.py tests/integration/test_planner_repair_entry.py tests/integration/test_repeated_pilot_entry.py tests/integration/test_attack_program_r3_semantics.py`。
- Ruff format/check 6目标、mypy 5源目标、bash -n 22/23入口、git diff --check通过；没有schema变更或候选准入放宽。
- 实际配置零请求preflight_valid，执行目录未创建，独立准备目录`r3-archive-diagnostic-20261001-v1-preparation/`保存计划/请求/prompt/preflight。计划hash `62efc6247d0d2585eee62239e9379b45497e27185e84c577ea61859316f91781`；逻辑请求/prompt保持旧身份，HTTP131072字节，文本65536字符，输出32768 tokens。
- 真实诊断尚待用户执行。具体历史触发规则与正文不可恢复；模式命中不等于真泄漏或误报。旧pilot不继续、不改源封存。
