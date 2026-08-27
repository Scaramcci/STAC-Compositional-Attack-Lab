from stac_attack_lab.cli import main

raise SystemExit(
    main(
        [
            "online",
            "run",
            "--config",
            "configs/experiments/mvp_online.yaml",
            "--dataset-version",
            "mvp-v0.1",
        ]
    )
)
