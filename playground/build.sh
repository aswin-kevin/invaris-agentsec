#!/usr/bin/env bash
# Build the invaris-agentsec wheel from this checkout into playground/vendor/agentsec.whl,
# which the playground's worker installs into Pyodide. Run from anywhere.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
python -m pip wheel --quiet --no-deps --wheel-dir "$tmp" "$root"
mkdir -p "$root/playground/vendor"
cp "$tmp"/invaris_agentsec-*-py3-none-any.whl "$root/playground/vendor/agentsec.whl"
echo "Built playground/vendor/agentsec.whl from $(basename "$tmp"/invaris_agentsec-*.whl)"
