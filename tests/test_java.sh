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
  "$ROOT/src/main/java/turboheader/il2cpp/metadata/Il2CppStringLabels.java" \
  "$ROOT/tests/java/turboheader/il2cpp/metadata/Il2CppStringLabelsTest.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/metadata/Il2CppMethodMetadataLabels.java" \
  "$ROOT/tests/java/turboheader/il2cpp/metadata/Il2CppMethodMetadataLabelsTest.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/types/CFunctionSignatureParser.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/analysis/helpers/Il2CppHelperKind.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/analysis/helpers/Il2CppHelperNames.java" \
  "$ROOT/tests/java/turboheader/il2cpp/analysis/helpers/Il2CppHelperNamesTest.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/analysis/interfacecall/ExactSsaValueResolver.java" \
  "$ROOT/tests/java/turboheader/il2cpp/analysis/interfacecall/ExactSsaValueResolverTest.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/analysis/ssa/SsaIdentityResolver.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/analysis/delegatecall/Il2CppDelegateCallProof.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/analysis/delegatecall/DelegateCallRejectionCounts.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/analysis/delegatecall/DelegateCallPrototype.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/analysis/interfacecall/TypeInfoSourcePolicy.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/analysis/interfacecall/Il2CppInterfaceCallProof.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/analysis/interfacecall/InterfaceCallRejectionCounts.java" \
  "$ROOT/tests/java/turboheader/il2cpp/analysis/interfacecall/Il2CppInterfaceCallProofTest.java" \
  "$ROOT/tests/java/turboheader/il2cpp/analysis/ssa/SsaIdentityResolverTest.java" \
  "$ROOT/tests/java/turboheader/il2cpp/analysis/delegatecall/Il2CppDelegateCallProofTest.java" \
  "$ROOT/tests/java/turboheader/il2cpp/analysis/delegatecall/DelegateCallRejectionCountsTest.java" \
  "$ROOT/tests/java/turboheader/il2cpp/analysis/delegatecall/DelegateCallPrototypeTest.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/metadata/SharedGenericCallSignature.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/analysis/sharedgeneric/SharedGenericCallProof.java" \
  "$ROOT/tests/java/turboheader/il2cpp/analysis/sharedgeneric/SharedGenericCallProofTest.java" \
  "$ROOT/tests/java/turboheader/il2cpp/analysis/interfacecall/TypeInfoSourcePolicyTest.java" \
  "$ROOT/tests/java/turboheader/il2cpp/analysis/interfacecall/InterfaceCallRejectionCountsTest.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/analysis/helpers/Il2CppHelperProofPolicy.java" \
  "$ROOT/tests/java/turboheader/il2cpp/analysis/helpers/Il2CppHelperProofPolicyTest.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/types/ImportDiagnostics.java" \
  "$ROOT/tests/java/turboheader/il2cpp/types/ImportDiagnosticsTest.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/types/CParserHeaderAdapter.java" \
  "$ROOT/tests/java/turboheader/il2cpp/types/CParserHeaderAdapterTest.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/metadata/MethodAssemblyIdentity.java" \
  "$ROOT/tests/java/turboheader/il2cpp/metadata/MethodAssemblyIdentityTest.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/model/TypeModel.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/model/ModelDecoder.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/NativeLibraryLoader.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/NativeParser.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/ModelDumpCli.java" \
  "$ROOT/tests/java/turboheader/il2cpp/model/CoreSmokeTest.java" \
  "$ROOT/tests/java/turboheader/il2cpp/JniSmokeTest.java"
java -cp "$BUILD/classes" turboheader.il2cpp.types.ImportDiagnosticsTest
java -cp "$BUILD/classes" turboheader.il2cpp.types.CParserHeaderAdapterTest
java -cp "$BUILD/classes" turboheader.il2cpp.metadata.MethodAssemblyIdentityTest
java -cp "$BUILD/classes" turboheader.il2cpp.metadata.Il2CppStringLabelsTest
java -cp "$BUILD/classes" turboheader.il2cpp.metadata.Il2CppMethodMetadataLabelsTest
java -cp "$BUILD/classes" turboheader.il2cpp.analysis.helpers.Il2CppHelperNamesTest
java -cp "$BUILD/classes" turboheader.il2cpp.analysis.interfacecall.ExactSsaValueResolverTest
java -cp "$BUILD/classes" turboheader.il2cpp.analysis.interfacecall.Il2CppInterfaceCallProofTest
java -cp "$BUILD/classes" turboheader.il2cpp.analysis.ssa.SsaIdentityResolverTest
java -cp "$BUILD/classes" turboheader.il2cpp.analysis.delegatecall.Il2CppDelegateCallProofTest
java -cp "$BUILD/classes" turboheader.il2cpp.analysis.delegatecall.DelegateCallRejectionCountsTest
java -cp "$BUILD/classes" turboheader.il2cpp.analysis.delegatecall.DelegateCallPrototypeTest
java -cp "$BUILD/classes" turboheader.il2cpp.analysis.sharedgeneric.SharedGenericCallProofTest
java -cp "$BUILD/classes" turboheader.il2cpp.analysis.interfacecall.TypeInfoSourcePolicyTest
java -cp "$BUILD/classes" turboheader.il2cpp.analysis.interfacecall.InterfaceCallRejectionCountsTest
java -cp "$BUILD/classes" turboheader.il2cpp.analysis.helpers.Il2CppHelperProofPolicyTest

javac --release 21 -cp "$BUILD/classes" -d "$BUILD/classes" \
  "$ROOT/src/main/java/turboheader/il2cpp/Il2CppExportScope.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/exporting/Il2CppClassCatalog.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/exporting/Il2CppClassSelector.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/decompile/Il2CppFunctionMatcher.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/exporting/PortableFilenameEncoder.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/exporting/Il2CppOutputPathAllocator.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/exporting/Il2CppOutputPath.java" \
  "$ROOT/tests/java/turboheader/il2cpp/exporting/Il2CppClassCatalogTest.java" \
  "$ROOT/tests/java/turboheader/il2cpp/decompile/Il2CppFunctionMatcherTest.java" \
  "$ROOT/tests/java/turboheader/il2cpp/exporting/Il2CppOutputPathTest.java"
java -cp "$BUILD/classes" turboheader.il2cpp.exporting.Il2CppClassCatalogTest
java -cp "$BUILD/classes" turboheader.il2cpp.decompile.Il2CppFunctionMatcherTest
java -cp "$BUILD/classes" turboheader.il2cpp.exporting.Il2CppOutputPathTest

javac --release 21 -cp "$BUILD/classes" -d "$BUILD/classes" \
  "$ROOT/tests/java/turboheader/il2cpp/types/CFunctionSignatureParserTest.java"
java -cp "$BUILD/classes" turboheader.il2cpp.types.CFunctionSignatureParserTest

javac --release 21 -cp "$BUILD/classes" -d "$BUILD/classes" \
  "$ROOT/src/main/java/turboheader/il2cpp/analysis/architecture/ArchitectureHelperProof.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/analysis/architecture/ControlFlowDecoder.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/analysis/architecture/aarch64/Aarch64Architecture.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/analysis/architecture/aarch64/Aarch64ControlFlowDecoder.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/analysis/architecture/aarch64/Aarch64InterfaceDispatchProof.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/analysis/noreturn/NoreturnSeedReader.java" \
  "$ROOT/src/main/java/turboheader/il2cpp/analysis/noreturn/NoreturnProofEngine.java" \
  "$ROOT/tests/java/turboheader/il2cpp/analysis/architecture/aarch64/Aarch64InterfaceDispatchProofTest.java" \
  "$ROOT/tests/java/turboheader/il2cpp/analysis/noreturn/NoreturnProofEngineTest.java" \
  "$ROOT/tests/java/turboheader/il2cpp/analysis/noreturn/NoreturnSeedReaderTest.java"
java -cp "$BUILD/classes" \
  turboheader.il2cpp.analysis.architecture.aarch64.Aarch64InterfaceDispatchProofTest
java -cp "$BUILD/classes" turboheader.il2cpp.analysis.noreturn.NoreturnProofEngineTest
java -cp "$BUILD/classes" turboheader.il2cpp.analysis.noreturn.NoreturnSeedReaderTest

if [[ -n "${GHIDRA_INSTALL_DIR:-}" ]]; then
  GSON_JAR="$(find "$GHIDRA_INSTALL_DIR/Ghidra" -name 'gson-*.jar' -type f | head -n 1)"
  [[ -n "$GSON_JAR" ]] || { printf 'Gson jar not found under Ghidra\n' >&2; exit 1; }
  javac --release 21 -cp "$GSON_JAR:$BUILD/classes" -d "$BUILD/classes" \
    "$ROOT/src/main/java/turboheader/il2cpp/Il2CppExportScope.java" \
    "$ROOT/src/main/java/turboheader/il2cpp/decompile/Il2CppDecompilationPolicy.java" \
    "$ROOT/src/main/java/turboheader/il2cpp/HeadlessRequestReader.java" \
    "$ROOT/tests/java/turboheader/il2cpp/HeadlessRequestReaderTest.java" \
    "$ROOT/src/main/java/turboheader/il2cpp/metadata/ScriptMethodReader.java" \
    "$ROOT/src/main/java/turboheader/il2cpp/metadata/Il2CppInterfaceDispatchCatalog.java" \
    "$ROOT/src/main/java/turboheader/il2cpp/metadata/Il2CppInterfaceDispatchCodec.java" \
    "$ROOT/src/main/java/turboheader/il2cpp/metadata/Il2CppDelegateSignatureCatalog.java" \
    "$ROOT/src/main/java/turboheader/il2cpp/metadata/Il2CppDelegateSignatureCodec.java" \
    "$ROOT/src/main/java/turboheader/il2cpp/metadata/Il2CppSharedGenericCallCatalog.java" \
    "$ROOT/src/main/java/turboheader/il2cpp/metadata/Il2CppSharedGenericCallCodec.java" \
    "$ROOT/src/main/java/turboheader/il2cpp/metadata/ReferenceGenericCallSignature.java" \
    "$ROOT/src/main/java/turboheader/il2cpp/metadata/Il2CppReferenceGenericCallCatalog.java" \
    "$ROOT/src/main/java/turboheader/il2cpp/metadata/Il2CppReferenceGenericCallCodec.java" \
    "$ROOT/tests/java/turboheader/il2cpp/metadata/Il2CppReferenceGenericCallCatalogTest.java" \
    "$ROOT/tests/java/turboheader/il2cpp/metadata/ScriptMethodReaderTest.java" \
    "$ROOT/tests/java/turboheader/il2cpp/metadata/Il2CppInterfaceDispatchCatalogTest.java" \
    "$ROOT/tests/java/turboheader/il2cpp/metadata/Il2CppDelegateSignatureCatalogTest.java" \
    "$ROOT/tests/java/turboheader/il2cpp/metadata/Il2CppSharedGenericCallCatalogTest.java"
  java -cp "$GSON_JAR:$BUILD/classes" turboheader.il2cpp.HeadlessRequestReaderTest
  java -cp "$GSON_JAR:$BUILD/classes" turboheader.il2cpp.metadata.ScriptMethodReaderTest \
    ${TURBOHEADER_SCRIPT_CORPUS:+"$TURBOHEADER_SCRIPT_CORPUS"}
  java -cp "$GSON_JAR:$BUILD/classes" \
    turboheader.il2cpp.metadata.Il2CppInterfaceDispatchCatalogTest
  java -cp "$GSON_JAR:$BUILD/classes" \
    turboheader.il2cpp.metadata.Il2CppDelegateSignatureCatalogTest
  java -cp "$GSON_JAR:$BUILD/classes" \
    turboheader.il2cpp.metadata.Il2CppSharedGenericCallCatalogTest
  java -cp "$GSON_JAR:$BUILD/classes" \
    turboheader.il2cpp.metadata.Il2CppReferenceGenericCallCatalogTest

  bash "$ROOT/tests/test_delegate_workers.sh"
fi

if [[ "${TURBOHEADER_JNI_ONLY:-0}" != "1" ]]; then
  MODEL="$BUILD/sample.i2gf"
  "$NATIVE_BUILD/il2cpp_native_cli" \
    "$ROOT/tests/fixtures/sample.h" "$ROOT/tests/fixtures/type_offsets.json" "$MODEL" 8 >/dev/null
  java -cp "$BUILD/classes" turboheader.il2cpp.model.CoreSmokeTest "$MODEL"
fi
NATIVE_LIBRARY="$(find_native_library "$NATIVE_BUILD")"
java -Xcheck:jni -Dturboheader.il2cpp.native="$NATIVE_LIBRARY" \
  -cp "$BUILD/classes" turboheader.il2cpp.JniSmokeTest \
  "$ROOT/tests/fixtures/sample.h" "$ROOT/tests/fixtures/type_offsets.json"
