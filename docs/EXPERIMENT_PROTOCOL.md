# Experiment Protocol

## Request-boundary evidence contract (experimental engineering policy)

The evidence layers are independent and strictly non-transitive:

1. **A: observed tool execution** means that a tool call/result pair was observed in the
   controlled runtime transcript.
2. **B: provider-request context reachability** means that a projection of one specific tool
   result was present in the final serialized payload of one actual provider attempt, after
   tool filtering and provider compatibility transforms. A timed-out or transport-failed
   attempt remains `attempted`; it does not prove provider receipt or model processing.
3. **C: deterministic argument derivation** means that an independently selected source
   artifact and a predeclared target tool argument satisfy a versioned mechanical rule using
   the evidence for the same request and response. It does not prove internal model reasoning,
   necessity, counterfactual causality, or benchmark effect.
4. **D: benchmark effect / official outcome** is evaluator-owned and is never inferred from
   A, B, or C.

A does not imply B, B does not imply C, and C does not imply D. Transcript adjacency,
`inputToolResultCallIds`, user text that resembles a tool result, model self-report, substring
overlap, or an event-wide label are not evidence for B or C.

### Proposed rule `stac.experimental.exact_tool_result_to_argument.v1`

This rule is an engineering validation policy and is not an approved research criterion. It is
disabled by default and cannot admit the formal path unless explicitly selected for a synthetic
or fake integration audit.

- **Source type:** one OpenAI-compatible request message whose role is exactly `tool`, whose
  `tool_call_id` is a non-empty string, and whose `content` is one complete, non-empty string.
  User/assistant messages, content block arrays, binary/image values, wrappers, truncated values,
  unavailable/disabled results, and tool errors are unsupported.
- **Target type:** one tool call in the response to that same request. The tool name and RFC 6901
  JSON Pointer are configured before the request. `function.arguments` must be the complete UTF-8
  JSON text for an object/array and the selected value must be one non-empty string.
- **Encoding:** source and target strings are encoded directly as UTF-8. JSON is decoded once;
  JSON string escaping is interpreted by the decoder. No Unicode normalization, newline rewrite,
  whitespace trimming, case folding, wrapper removal, or substring search is performed.
- **Projection:** `utf8-string-v1`; hashes are SHA-256 over the exact UTF-8 bytes. Full bounded
  projections and full arguments JSON are retained only when the disabled experimental policy is
  explicitly enabled for synthetic data. Display excerpts and redacted placeholders are never
  inputs to this rule.
- **Binding:** source artifact/version selection comes first from graph lineage. The verifier then
  requires its tool-result call, request ID, response, target tool-call ID, action, actual session,
  workspace, batch, record hashes, and evidence-file hash to agree. It never searches arbitrary
  fields for a convenient equality.
- **Result:** exact byte equality establishes only this declared input-to-argument transformation.
  Empty, oversized, malformed, partial, wrapped, unknown-rule, ambiguous duplicate-call, cross-run,
  cross-session, cross-workspace, or conflicting evidence yields `unknown` or `failed` with a
  stable reason code.

Request evidence is captured before the upstream call from the final serialized payload. A
`prepared` record must be durably written before network I/O; `attempted` is written immediately
before the call; `response_received` is written only after an HTTP response is obtained and its
bounded response projection is parsed. Each retry has a new request/attempt ID and append-only
records. A bridge-controlled context record supplies action/workspace/session binding; model text
cannot set or override it. Evidence metadata is local and is not added to the upstream payload.

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
