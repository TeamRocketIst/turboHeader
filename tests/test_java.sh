#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/tests/build-java"
NATIVE_BUILD="${TURBOHEADER_NATIVE_BUILD_DIR:-$ROOT/native/build-clean}"
source "$ROOT/tests/lib.sh"
configure_java_home
rm -rf "$BUILD"
mkdir -p "$BUILD/classes"

javac --release 21 -d "$BUILD/classes" \
  "$ROOT/src/main/java/turboheader/il2cpp/Il2CppStringLabels.java" \
  "$ROOT/tests/java/turboheader/il2cpp/Il2CppStringLabelsTest.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/Il2CppMethodMetadataLabels.java" \
  "$ROOT/tests/java/turboheader/il2cpp/Il2CppMethodMetadataLabelsTest.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/Il2CppHelperKind.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/Il2CppHelperNames.java" \
  "$ROOT/tests/java/turboheader/il2cpp/Il2CppHelperNamesTest.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/Il2CppHelperProofPolicy.java" \
  "$ROOT/tests/java/turboheader/il2cpp/Il2CppHelperProofPolicyTest.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/ImportDiagnostics.java" \
  "$ROOT/tests/java/turboheader/il2cpp/ImportDiagnosticsTest.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/MethodAssemblyIdentity.java" \
  "$ROOT/tests/java/turboheader/il2cpp/MethodAssemblyIdentityTest.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/TypeModel.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/ModelDecoder.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/NativeLibraryLoader.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/NativeParser.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/ModelDumpCli.java" \
  "$ROOT/tests/java/turboheader/il2cpp/CoreSmokeTest.java" \
  "$ROOT/tests/java/turboheader/il2cpp/JniSmokeTest.java"
java -cp "$BUILD/classes" turboheader.il2cpp.ImportDiagnosticsTest
java -cp "$BUILD/classes" turboheader.il2cpp.MethodAssemblyIdentityTest
java -cp "$BUILD/classes" turboheader.il2cpp.Il2CppStringLabelsTest
java -cp "$BUILD/classes" turboheader.il2cpp.Il2CppMethodMetadataLabelsTest
java -cp "$BUILD/classes" turboheader.il2cpp.Il2CppHelperNamesTest
java -cp "$BUILD/classes" turboheader.il2cpp.Il2CppHelperProofPolicyTest

javac --release 21 -d "$BUILD/classes" \
  "$ROOT/src/main/java/turboheader/il2cpp/CFunctionSignatureParser.java" \
  "$ROOT/tests/java/turboheader/il2cpp/CFunctionSignatureParserTest.java"
java -cp "$BUILD/classes" turboheader.il2cpp.CFunctionSignatureParserTest

javac --release 21 -d "$BUILD/classes" \
  "$ROOT/src/main/java/turboheader/il2cpp/Aarch64ControlFlowDecoder.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/NoreturnSeedReader.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/NoreturnProofEngine.java" \
  "$ROOT/tests/java/turboheader/il2cpp/NoreturnProofEngineTest.java" \
  "$ROOT/tests/java/turboheader/il2cpp/NoreturnSeedReaderTest.java"
java -cp "$BUILD/classes" turboheader.il2cpp.NoreturnProofEngineTest
java -cp "$BUILD/classes" turboheader.il2cpp.NoreturnSeedReaderTest

if [[ -n "${GHIDRA_INSTALL_DIR:-}" ]]; then
  GSON_JAR="$(find "$GHIDRA_INSTALL_DIR/Ghidra" -name 'gson-*.jar' -type f | head -n 1)"
  [[ -n "$GSON_JAR" ]] || { printf 'Gson jar not found under Ghidra\n' >&2; exit 1; }
  javac --release 21 -cp "$GSON_JAR:$BUILD/classes" -d "$BUILD/classes" \
    "$ROOT/src/main/java/turboheader/il2cpp/ScriptMethodReader.java" \
    "$ROOT/tests/java/turboheader/il2cpp/ScriptMethodReaderTest.java"
  java -cp "$GSON_JAR:$BUILD/classes" turboheader.il2cpp.ScriptMethodReaderTest \
    ${TURBOHEADER_SCRIPT_CORPUS:+"$TURBOHEADER_SCRIPT_CORPUS"}
fi

if [[ "${TURBOHEADER_JNI_ONLY:-0}" != "1" ]]; then
  MODEL="$BUILD/sample.i2gf"
  "$NATIVE_BUILD/il2cpp_native_cli" \
    "$ROOT/tests/fixtures/sample.h" "$ROOT/tests/fixtures/type_offsets.json" "$MODEL" 8 >/dev/null
  java -cp "$BUILD/classes" turboheader.il2cpp.CoreSmokeTest "$MODEL"
fi
NATIVE_LIBRARY="$(find_native_library "$NATIVE_BUILD")"
java -Xcheck:jni -Dturboheader.il2cpp.native="$NATIVE_LIBRARY" \
  -cp "$BUILD/classes" turboheader.il2cpp.JniSmokeTest \
  "$ROOT/tests/fixtures/sample.h" "$ROOT/tests/fixtures/type_offsets.json"
