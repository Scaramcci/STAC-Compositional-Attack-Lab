# Experiment Protocol

## Gate sequence

```text
environment preflight
  -> pilot collection
  -> pilot mining and audit
  -> main collection
  -> main mining, audit, and freeze
  -> formal preflight
  -> matched formal evaluation
  -> run audit and report
```

Pilot 必须获得至少 2 个 accepted samples；main 必须获得至少 30 个。任何 gate 失败都禁止进入下一阶段。

## Formal design

当前矩阵为 1 个 PSE 2.1 task × 3 conditions × 5 seeds。三个条件是 `assigned_sample`、`no_sample` 和 `dependency_ablation`。

Matched pair 内保持 task、seed、public prompt、budget、target model、environment、registry、library 和 official evaluator 相同。Dependency ablation 只能修改 task set 预注册的一个 sample-derived slot。

## Acceptance evidence

Sample acceptance 要求 observable occurrence、typed causal edge、trust-boundary crossing、terminal relation、完整 provenance 和 no-shortcut evidence。语义判断不能覆盖缺失的 hard evidence。

## Metrics

- official success rate；
- mechanism-complete rate；
- official/mechanism agreement；
- dependency-ablation effect；
- failed primitive 和 reason code；
- tool、token、session 和 wall-time accounting。

Matched binary comparison 使用 McNemar exact test；比例报告 Wilson interval。缺失、abandoned 或审计失败的 case 不得静默计为成功。

## Reproducibility

所有报告必须从持久化 manifest、assignment、events、verdicts 和 complete interaction record 重建。Frozen library 不得覆盖；恢复运行必须验证 config、registry、library 和 case matrix hash。

## Stop conditions

Preflight、pilot threshold、library audit、secret scan、view separation、pair invariant、action lineage、official evaluator 或 complete-matrix audit 任一失败，实验立即停止并保留失败证据。
