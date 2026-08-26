#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/lib.sh"
configure_java_home

if [[ -z "${GHIDRA_INSTALL_DIR:-}" ]]; then
  printf 'GHIDRA_INSTALL_DIR is required for the real-Ghidra suite\n' >&2
  exit 2
fi

HEADLESS="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
[[ -f "$HEADLESS" ]] || { printf 'analyzeHeadless not found under %s\n' "$GHIDRA_INSTALL_DIR" >&2; exit 2; }

TEST_TEMP="${TURBOHEADER_TEST_TEMP:-${TMPDIR:-/tmp}}"
mkdir -p "$TEST_TEMP"
PROJECT_ROOT="$(mktemp -d "$TEST_TEMP/turboheader-ghidra.XXXXXX")"
JAVA_PROJECT_ROOT="$PROJECT_ROOT"
if command -v cygpath >/dev/null 2>&1; then
  JAVA_PROJECT_ROOT="$(cygpath -m "$PROJECT_ROOT")"
fi
TEST_BINARY="${GHIDRA_TEST_BINARY:-}"
if [[ -z "$TEST_BINARY" ]]; then
  if command -v cygpath >/dev/null 2>&1 && [[ -n "${COMSPEC:-}" ]]; then
    TEST_BINARY="$(cygpath -u "$COMSPEC")"
  else
    TEST_BINARY="$(command -v ls)"
  fi
fi
JAVA_TEST_BINARY="$TEST_BINARY"
if command -v cygpath >/dev/null 2>&1; then
  JAVA_TEST_BINARY="$(cygpath -m "$TEST_BINARY")"
fi
EXTENSION_DIR="$GHIDRA_INSTALL_DIR/Ghidra/Extensions/turboheader-ghidra-il2cpp"
EXTENSION_BACKUP="$PROJECT_ROOT/installed-extension-backup"
restore_extension() {
  rm -rf "$EXTENSION_DIR"
  if [[ -d "$EXTENSION_BACKUP" ]]; then
    mv "$EXTENSION_BACKUP" "$EXTENSION_DIR"
  fi
  rm -rf "$PROJECT_ROOT"
}
trap restore_extension EXIT

ZIP="${TURBOHEADER_EXTENSION_ZIP:-}"
if [[ -z "$ZIP" ]]; then
  rm -rf "$ROOT/dist"
  (cd "$ROOT" && ./gradlew --no-daemon buildExtension >/dev/null)
  archives=("$ROOT"/dist/*.zip)
  [[ "${#archives[@]}" -eq 1 && -f "${archives[0]}" ]] || {
    printf 'expected one extension archive, found %s\n' "${#archives[@]}" >&2
    exit 1
  }
  ZIP="${archives[0]}"
fi
[[ -n "$ZIP" ]] || { printf 'extension archive was not produced\n' >&2; exit 1; }
[[ -f "$ZIP" ]] || { printf 'extension archive does not exist: %s\n' "$ZIP" >&2; exit 1; }
python3 "$ROOT/tools/verify_extension.py" "$ZIP"
if [[ -d "$EXTENSION_DIR" ]]; then
  mv "$EXTENSION_DIR" "$EXTENSION_BACKUP"
fi
python3 -m zipfile -e "$ZIP" "$GHIDRA_INSTALL_DIR/Ghidra/Extensions"

LOG="$PROJECT_ROOT/headless.log"
JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:+$JAVA_TOOL_OPTIONS }-Dapplication.settingsdir=$JAVA_PROJECT_ROOT/settings -Dapplication.cachedir=$JAVA_PROJECT_ROOT/cache" \
  bash "$HEADLESS" "$PROJECT_ROOT" TurboHeaderFixture \
  -import "$JAVA_TEST_BINARY" -noanalysis \
  -scriptPath "$ROOT/ghidra_scripts;$ROOT/tests/ghidra_scripts" \
  -postScript ImportIl2CppTypes.java \
  "$ROOT/tests/fixtures/sample.h" "$ROOT/tests/fixtures/type_offsets.json" \
  -postScript VerifyTurboHeaderFixture.java \
  -postScript VerifyTurboHeaderTransactions.java \
  "$ROOT/tests/fixtures/sample.h" "$ROOT/tests/fixtures/type_offsets.json" 8 \
  -postScript VerifyTurboHeaderProvenance.java \
  "$ROOT/tests/fixtures/sample.h" "$ROOT/tests/fixtures/type_offsets.json" 8 \
  -postScript ImportIl2CppTypes.java \
  "$ROOT/tests/fixtures/class_metadata.h" "$ROOT/tests/fixtures/class_metadata_offsets.json" - \
  require-external-offsets \
  -postScript VerifyTurboHeaderClassMetadata.java \
  -postScript VerifyGhidraFullHeaderStaticFields.java \
  -postScript VerifyTurboHeaderCallingConvention.java \
  -deleteProject 2>&1 | tee "$LOG"

grep -q 'TurboHeader real-Ghidra fixture verification passed' "$LOG"
grep -q 'TurboHeader real-Ghidra transaction tests passed' "$LOG"
grep -q 'TurboHeader real-Ghidra provenance verification passed' "$LOG"
grep -q 'TurboHeader class metadata verification passed' "$LOG"
grep -q 'Ghidra full-header static-field verification passed' "$LOG"
grep -q 'TurboHeader calling-convention verification passed' "$LOG"
grep -q 'REPORT: Import succeeded' "$LOG"
printf 'real Ghidra headless tests passed\n'
