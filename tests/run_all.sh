#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/lib.sh"
configure_java_home

rm -rf "$ROOT/native/build-clean"
cmake -S "$ROOT/native" -B "$ROOT/native/build-clean" -DCMAKE_BUILD_TYPE=Release \
  -DTURBOHEADER_STRICT_WARNINGS=ON -DTURBOHEADER_WARNINGS_AS_ERRORS=ON >/dev/null
cmake --build "$ROOT/native/build-clean" --parallel

PYTHONPATH="$ROOT/tests" python3 "$ROOT/tests/test_native.py"
python3 "$ROOT/tests/test_packaging.py"
python3 "$ROOT/tests/test_release_workflow.py"
python3 "$ROOT/tests/test_exporter.py"
"$ROOT/tests/test_headless_workflow.sh"
"$ROOT/tests/test_java.sh"
"$ROOT/tests/test_ghidra_harness.sh"

rm -rf "$ROOT/native/build-sanitize"
cmake -S "$ROOT/native" -B "$ROOT/native/build-sanitize" -DCMAKE_BUILD_TYPE=Debug \
  -DTURBOHEADER_STRICT_WARNINGS=ON -DTURBOHEADER_WARNINGS_AS_ERRORS=ON \
  -DTURBOHEADER_ENABLE_SANITIZERS=ON >/dev/null
cmake --build "$ROOT/native/build-sanitize" --parallel >/dev/null
TURBOHEADER_SANITIZER_BUILD_DIR="$ROOT/native/build-sanitize" \
  python3 "$ROOT/tests/test_sanitizers.py"

if [[ -n "${GHIDRA_INSTALL_DIR:-}" ]]; then
  "$ROOT/tests/test_real_ghidra.sh"
fi
