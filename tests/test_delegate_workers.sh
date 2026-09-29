#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/lib.sh"
configure_java_home
[[ -n "${GHIDRA_INSTALL_DIR:-}" ]] || {
  printf 'GHIDRA_INSTALL_DIR is required for delegate worker tests\n' >&2
  exit 2
}

BUILD="$(mktemp -d "${TMPDIR:-/tmp}/turboheader-delegate-tests.XXXXXX")"
trap 'rm -rf "$BUILD"' EXIT
DELEGATE_CLASSPATH="$BUILD"
while IFS= read -r -d '' jar; do
  DELEGATE_CLASSPATH="$DELEGATE_CLASSPATH:$jar"
done < <(find "$GHIDRA_INSTALL_DIR/Ghidra" -name '*.jar' -type f -print0)
JAVA_ROOT="$ROOT"
JAVA_BUILD="$BUILD"
if command -v cygpath >/dev/null 2>&1; then
  JAVA_ROOT="$(cygpath -m "$ROOT")"
  JAVA_BUILD="$(cygpath -m "$BUILD")"
  DELEGATE_CLASSPATH="$(cygpath -wp "$DELEGATE_CLASSPATH")"
fi
javac --release 21 -proc:none -cp "$DELEGATE_CLASSPATH" -d "$JAVA_BUILD" \
  -sourcepath "$JAVA_ROOT/src/main/java" \
  "$JAVA_ROOT/tests/java/turboheader/il2cpp/analysis/delegatecall/DelegateProofCoordinatorTest.java"
java -cp "$DELEGATE_CLASSPATH" turboheader.il2cpp.analysis.delegatecall.DelegateProofCoordinatorTest
