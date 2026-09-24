"""Offline F5 repeat plan compiler and read-only review entry."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from stac_attack_lab.capability.f5_repeats import (
    GROUPS,
    prepare_f5_repeats,
    report_f5_repeats,
    validate_f5_repeats,
)
from stac_attack_lab.capability.m3_f5 import recompute_f5_episode


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("prepare", "validate", "report", "group-root", "ready"))
    parser.add_argument("plan_root", type=Path)
    parser.add_argument("extra", nargs="*")
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[2]
    if args.mode == "prepare":
        if args.extra:
            parser.error("prepare takes no extra arguments")
        path = prepare_f5_repeats(
            project, project / "configs/capability/m3b_f5_repeat.disabled.json", args.plan_root
        )
        print(path)
        return
    plan = validate_f5_repeats(project, args.plan_root)
    if args.mode == "validate":
        if args.extra:
            parser.error("validate takes no extra arguments")
        print(json.dumps({"plan_hash": plan["plan_hash"], "denominator": 9, "bound": False}))
    elif args.mode == "report":
        if len(args.extra) != 1:
            parser.error("report requires a new output path")
        print(report_f5_repeats(project, args.plan_root, Path(args.extra[0])))
    else:
        if len(args.extra) != 1 or args.extra[0] not in GROUPS:
            parser.error("group-root requires r01, r02, or r03")
        if args.mode == "ready":
            for prior in GROUPS[: GROUPS.index(args.extra[0])]:
                for condition in plan["order"]:
                    episode = args.plan_root / prior / "results" / condition
                    result = episode / "episode_result.json"
                    if not result.is_file():
                        raise ValueError("f5_repeat_prior_group_incomplete")
                    review = recompute_f5_episode(episode)
                    if (
                        review["execution_status"] != "completed"
                        or review["cleanup_status"] != "completed"
                        or review["acceptance"]["measurement_readiness"] != "satisfied"
                    ):
                        raise ValueError("f5_repeat_prior_group_engineering_failure")
        print(args.plan_root / args.extra[0])


if __name__ == "__main__":
    main()
