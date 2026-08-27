# Data Layout

| 路径 | 数据阶段 | 可变性 |
|---|---|---|
| `seeds/` | legacy task/primitive seed | 版本控制 |
| `generated/` | legacy 未冻结构建产物 | 可恢复、默认忽略 |
| `frozen/` | legacy 审计后数据集 | 不可覆盖 |
| `interactions/raw/` | 通用 raw interaction | 生成、默认忽略 |
| `interactions/normalized/` | 通用标准化 graph | 生成、默认忽略 |
| `primitive_libraries/generated/` | formal collection、mining、audit 工作树 | 可恢复、默认忽略 |
| `primitive_libraries/frozen/` | 审计通过的 formal sample library | 不可覆盖 |
| `provenance/` | 模型、revision 和依赖来源 | 版本控制 |

`stac-verified-30-v0.1` 是历史 legacy 数据集。`formal-v2-attack-synthetic` 是 synthetic regression library。当前 formal-v2 需要的真实 `formal-v3-safeclaw-20260824` 尚不存在。

冻结目录是研究证据，不得就地编辑。新 collection、rerun 或 recovery 必须使用新的 version/output root。

