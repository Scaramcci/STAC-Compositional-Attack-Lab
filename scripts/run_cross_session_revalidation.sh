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
  *)
    echo "usage: $0 [prepare [--run-id ID] [--template PATH] | offline --run-root PATH [--collection PATH] [--library PATH]]" >&2
    exit 2
    ;;
esac
