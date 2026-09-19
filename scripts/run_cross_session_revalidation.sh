#!/usr/bin/env bash
# Versioned thin wrapper. It never enables live execution implicitly.
set -Eeuo pipefail
umask 077
cd "$(dirname "${BASH_SOURCE[0]}")/.."
PY="${STAC_PYTHON:-python}"
export PYTHONPATH="$PWD/src"
case "${1:-prepare}" in
  prepare)
    shift
    exec "$PY" -m stac_attack_lab.cli revalidation prepare "$@"
    ;;
  offline)
    shift
    exec "$PY" -m stac_attack_lab.cli revalidation offline "$@"
    ;;
  live)
    shift
    exec "$PY" -m stac_attack_lab.cli revalidation live "$@"
    ;;
  *)
    echo "usage: $0 [prepare ... | offline --run-root PATH ... | live --run-root PATH --authorize-live]" >&2
    exit 2
    ;;
esac
