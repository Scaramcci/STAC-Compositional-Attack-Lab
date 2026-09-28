# 当前脚本

`attack_program/` 是唯一的工作流脚本目录。所有输出目录必须尚不存在。

- `00_doctor.sh`：离线 pinned task/judge 检查。
- `01_catalog.sh`、`02_split.sh`：任务目录与组级 split。
- `03_develop.sh`、`04_library.sh`：离线开发样本与 synthetic 库。
- `08_results.sh`：状态与 replay/audit 包装入口。
- `10_demo_r2.sh`：R2 全尝试 synthetic 工程闭环。
- `11_demo_r3.sh`：R2 库、三臂多样本 Planner 与独立 replay/audit 总演示。

示例：

```bash
STAC_PYTHON=/home/scarramcci/miniconda3/envs/stac/bin/python bash scripts/attack_program/11_demo_r3.sh --output experiments/runs/attack-program/<new-id>
```

这些脚本不发送模型/API 请求，也不运行 Docker。
