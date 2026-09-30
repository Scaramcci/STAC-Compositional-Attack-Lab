from __future__ import annotations

import argparse
from pathlib import Path

from stac_attack_lab.attack_program.r4_real_diagnosis import diagnose_batch


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch-root", type=Path, required=True)
    parser.add_argument("--review-root", type=Path, required=True)
    parser.add_argument("--audit-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    diagnose_batch(args.batch_root, args.review_root, args.audit_root, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
