# 字段级诊断验证 — 2026-10-02

## 实際离线结果

先写反例：接口缺失7 failed；实现后新增生产loopback usage字符串泄露反例1 failed。修复后最终57 passed in 17.04s。无真实请求、Victim、bind或Docker。

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 /home/scarramcci/miniconda3/envs/stac/bin/python -m pytest -q tests/integration/test_planner_field_diagnostics.py tests/integration/test_planner_protection_diagnostics.py tests/integration/test_planner_failure_evidence.py tests/integration/test_planner_repair_entry.py tests/integration/test_repeated_pilot_entry.py
```

覆盖content/其他字段、敏感未知键、原始表示与解码值差异、多规则、多字段、重复键、非法JSON、深度/字节/节点/字段上限、正常响应、异常不保存秘密、生产HTTP归档阻断和plan not_evaluated、usage数字保留/字符串去除、既有入口身份/重复/预算测试。

Ruff format --check与check：5目标通过；mypy：4源目标通过；22 Bash bash -n通过；git diff --check通过。没有运行完整pytest/质量门。

## 零请求准备

preflight status diagnostic_preflight_valid，requests_sent=0；执行目录未创建。
准备目录：experiments/runs/attack-program/r3-field-diagnostic-20261002-v1-preparation/
计划hash：b63a67d4b4e71ba1ab50d2d746055c24b76c459074abf05361ffdeb478d1d7a3。
保存plan.json、request.json、effective-prompt.txt、preflight.json；execution_authorized=false。

历史HTTP200/32329字节/secret-assignment×3与content1662字符/零命中保持。具体历史字段和正文无法恢复。新响应不保证复现，也不能反推旧正文。用户单次终端执行仍待查收。
