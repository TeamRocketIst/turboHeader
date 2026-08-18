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
[[ -x "$HEADLESS" ]] || { printf 'analyzeHeadless not found under %s\n' "$GHIDRA_INSTALL_DIR" >&2; exit 2; }

PROJECT_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/turboheader-ghidra.XXXXXX")"
TEST_BINARY="${GHIDRA_TEST_BINARY:-$(command -v ls)}"
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

rm -rf "$ROOT/dist"
(cd "$ROOT" && ./gradlew --no-daemon buildExtension >/dev/null)
ZIP="$(find "$ROOT/dist" -maxdepth 1 -name '*.zip' -type f | head -n 1)"
[[ -n "$ZIP" ]] || { printf 'extension archive was not produced\n' >&2; exit 1; }

if unzip -Z1 "$ZIP" | grep -Eq '/(native|tests)/build-|__pycache__|\.pyc$|\.DS_Store$|\.i2gf$'; then
  printf 'extension archive contains a generated build artifact\n' >&2
  exit 1
fi

PLATFORM_DIR="$(java -XshowSettings:properties -version 2>&1 | awk -F'= ' '
  /os.name =/ { os=$2 }
  /os.arch =/ { arch=$2 }
  END {
    if (os ~ /Mac/) p="mac"; else if (os ~ /Windows/) p="win"; else p="linux";
    if (arch == "amd64" || arch == "x86_64") a="x86_64";
    else if (arch == "aarch64" || arch == "arm64") a="aarch64";
    print p "_" a;
  }')"
if ! unzip -Z1 "$ZIP" | grep -E "/os/${PLATFORM_DIR}/(lib)?turboheader_il2cpp\.(so|dylib|dll)$" >/dev/null; then
  printf 'extension archive does not contain the host native library for %s\n' "$PLATFORM_DIR" >&2
  exit 1
fi
if [[ -d "$EXTENSION_DIR" ]]; then
  mv "$EXTENSION_DIR" "$EXTENSION_BACKUP"
fi
unzip -q "$ZIP" -d "$GHIDRA_INSTALL_DIR/Ghidra/Extensions"

LOG="$PROJECT_ROOT/headless.log"
JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:+$JAVA_TOOL_OPTIONS }-Dapplication.settingsdir=$PROJECT_ROOT/settings -Dapplication.cachedir=$PROJECT_ROOT/cache" \
  "$HEADLESS" "$PROJECT_ROOT" TurboHeaderFixture \
  -import "$TEST_BINARY" -noanalysis \
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
