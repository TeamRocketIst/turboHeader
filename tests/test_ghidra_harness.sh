#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/tests/build-ghidra-harness"
source "$ROOT/tests/lib.sh"
configure_java_home
rm -rf "$BUILD"
mkdir -p "$BUILD/classes"
STUBS=()
while IFS= read -r stub; do
  STUBS+=("$stub")
done < <(find "$ROOT/tests/stubs" -name '*.java' -type f | sort)
javac --release 21 -d "$BUILD/classes" \
  "${STUBS[@]}" \
  "$ROOT/src/main/java/turboheader/il2cpp/TypeModel.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/ModelDecoder.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/NativeLibraryLoader.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/NativeParser.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/GhidraTypeImporter.java" \
  "$ROOT/tests/java/turboheader/il2cpp/GhidraImporterHarnessTest.java" \
  "$ROOT/tests/java/turboheader/il2cpp/GhidraImporterIntegrityTest.java" \
  "$ROOT/tests/java/turboheader/il2cpp/CorpusModelValidation.java" \
  "$ROOT/tests/ghidra_scripts/VerifyTurboHeaderFixture.java"
java -cp "$BUILD/classes" turboheader.il2cpp.GhidraImporterIntegrityTest
NATIVE_LIBRARY="$(find_native_library "$ROOT/native/build-clean")"
java -Dturboheader.il2cpp.native="$NATIVE_LIBRARY" \
  -cp "$BUILD/classes" turboheader.il2cpp.GhidraImporterHarnessTest \
  "$ROOT/tests/fixtures/sample.h" "$ROOT/tests/fixtures/type_offsets.json"
