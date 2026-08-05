#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VLLM_BIN="${VLLM_BIN:-${PROJECT_ROOT}/.venv-vllm/bin/vllm}"
VLLM_BIN_DIR="$(dirname "${VLLM_BIN}")"
export PATH="${VLLM_BIN_DIR}:${PATH}"
export VLLM_USE_FLASHINFER_SAMPLER="${VLLM_USE_FLASHINFER_SAMPLER:-0}"
DISCOVERY_PYTHON="${HUIHUI_DISCOVERY_PYTHON:-${PROJECT_ROOT}/.venv/bin/python}"
if [[ ! -x "${DISCOVERY_PYTHON}" && "${DISCOVERY_PYTHON}" == "${PROJECT_ROOT}/.venv/bin/python" ]]; then
  DISCOVERY_PYTHON="python3"
fi
MODEL_PATH="${HUIHUI_MODEL_PATH:-$(PYTHONPATH="${PROJECT_ROOT}/src" "${DISCOVERY_PYTHON}" -m stac_attack_lab.cli models discover-huihui)}"
SERVED_MODEL="${HUIHUI_MODEL:-huihui-qwen3-14b-abliterated-v2}"
HOST="${HUIHUI_HOST:-127.0.0.1}"
PORT="${HUIHUI_PORT:-8000}"

if [[ ! -x "${VLLM_BIN}" ]]; then
  echo "vLLM executable not found: ${VLLM_BIN}" >&2
  echo "Install vLLM in .venv-vllm or set VLLM_BIN explicitly." >&2
  exit 1
fi

EXTRA_ARGS=()
QUANTIZATION="${HUIHUI_QUANTIZATION:-bitsandbytes}"
if [[ "${QUANTIZATION}" != "none" ]]; then
  EXTRA_ARGS+=(--quantization "${QUANTIZATION}")
fi
if [[ -n "${HUIHUI_CPU_OFFLOAD_GB:-}" ]]; then
  EXTRA_ARGS+=(--cpu-offload-gb "${HUIHUI_CPU_OFFLOAD_GB}")
fi

exec "${VLLM_BIN}" serve "${MODEL_PATH}" \
  --served-model-name "${SERVED_MODEL}" \
  --host "${HOST}" \
  --port "${PORT}" \
  --dtype auto \
  --max-model-len "${HUIHUI_MAX_MODEL_LEN:-8192}" \
  --gpu-memory-utilization "${HUIHUI_GPU_MEMORY_UTILIZATION:-0.92}" \
  --max-num-seqs "${HUIHUI_MAX_NUM_SEQS:-1}" \
  --enable-prefix-caching \
  "${EXTRA_ARGS[@]}"
