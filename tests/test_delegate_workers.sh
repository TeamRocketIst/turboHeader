#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/lib.sh"
configure_java_home
[[ -n "${GHIDRA_INSTALL_DIR:-}" ]] || {
  printf 'GHIDRA_INSTALL_DIR is required for proof worker tests\n' >&2
  exit 2
}

BUILD="$(mktemp -d "${TMPDIR:-/tmp}/turboheader-delegate-tests.XXXXXX")"
trap 'rm -rf "$BUILD"' EXIT
DELEGATE_ENTRIES=("$BUILD")
while IFS= read -r -d '' jar; do
  DELEGATE_ENTRIES+=("$jar")
done < <(find "$GHIDRA_INSTALL_DIR/Ghidra" -name '*.jar' -type f -print0)
DELEGATE_CLASSPATH="$(java_classpath "${DELEGATE_ENTRIES[@]}")"
JAVA_ROOT="$ROOT"
JAVA_BUILD="$BUILD"
if command -v cygpath >/dev/null 2>&1; then
  JAVA_ROOT="$(cygpath -m "$ROOT")"
  JAVA_BUILD="$(cygpath -m "$BUILD")"
  export MSYS2_ARG_CONV_EXCL='*'
fi
javac --release 21 -proc:none -cp "$DELEGATE_CLASSPATH" -d "$JAVA_BUILD" \
  -sourcepath "$JAVA_ROOT/src/main/java" \
  "$JAVA_ROOT/tests/java/turboheader/il2cpp/analysis/pipeline/FunctionProofCoordinatorTest.java" \
  "$JAVA_ROOT/tests/java/turboheader/il2cpp/analysis/delegatecall/DelegateProofWorkerTest.java" \
  "$JAVA_ROOT/tests/java/turboheader/il2cpp/analysis/interfacecall/InterfaceProofWorkerTest.java"
java -cp "$DELEGATE_CLASSPATH" turboheader.il2cpp.analysis.pipeline.FunctionProofCoordinatorTest
java -cp "$DELEGATE_CLASSPATH" turboheader.il2cpp.analysis.delegatecall.DelegateProofWorkerTest
java -cp "$DELEGATE_CLASSPATH" turboheader.il2cpp.analysis.interfacecall.InterfaceProofWorkerTest
