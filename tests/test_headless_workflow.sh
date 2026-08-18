#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
TMP="$(cd "$TMP" && pwd -P)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/input files" "$TMP/bin" "$TMP/ghidra/support" "$TMP/output/com.example.game/out_il2"
: > "$TMP/input files/libil2cpp.so"
: > "$TMP/input files/global-metadata.dat"
: > "$TMP/output/com.example.game/out_il2/stale"

cat > "$TMP/bin/il2cpp" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" > "$MOCK_IL2CPP_ARGS"
output="$3"
mkdir -p "$output"
printf 'struct Example_Fields { int value; };\n' > "$output/il2cpp.h"
printf '{"version":3,"pointerSize":8,"types":{}}\n' > "$output/type_offsets.json"
printf '{"ScriptMethod":[],"ScriptMetadata":[]}\n' > "$output/script.json"
EOF
chmod +x "$TMP/bin/il2cpp"

cat > "$TMP/ghidra/support/analyzeHeadless" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" > "$MOCK_GHIDRA_ARGS"
touch "$1/$2.gpr"
printf 'TurboHeader metadata: 0 read, 0 labels created, 0 globals typed, 0 relocation slots typed, 0 failed in 0.000 s.\n'
printf 'TurboHeader methods: 0 read, 0 applied, 0 functions created, 0 failed in 0.000 s\n'
printf 'TurboHeader layout evidence: source=TYPE_OFFSETS_JSON schema=3; 0 header-inferred offsets\n'
EOF
chmod +x "$TMP/ghidra/support/analyzeHeadless"

export MOCK_IL2CPP_ARGS="$TMP/il2cpp.args"
export MOCK_GHIDRA_ARGS="$TMP/ghidra.args"
export GHIDRA_INSTALL_DIR="$TMP/ghidra"
export IL2CPP_BIN="$TMP/bin/il2cpp"
export TURBOHEADER_OUTPUT_ROOT="$TMP/output"

"$ROOT/tools/import_headless.sh" \
    "$TMP/input files/libil2cpp.so" \
    "$TMP/input files/global-metadata.dat" \
    com.example.game \
    2022.3.62f2 >/dev/null

generated="$TMP/output/com.example.game/out_il2"
[[ ! -e "$generated/stale" ]]
grep -Fx "$generated/il2cpp.h" "$MOCK_GHIDRA_ARGS" >/dev/null
grep -Fx "$generated/type_offsets.json" "$MOCK_GHIDRA_ARGS" >/dev/null
grep -Fx "$generated/script.json" "$MOCK_GHIDRA_ARGS" >/dev/null
if grep -Fx '8' "$MOCK_GHIDRA_ARGS" >/dev/null; then
    printf 'explicit pointer size reached ImportIl2CppTypes.java\n' >&2
    exit 1
fi
grep -Fx 'require-external-offsets' "$MOCK_GHIDRA_ARGS" >/dev/null
if grep -F 'il2cpp_ghidra.h' "$MOCK_GHIDRA_ARGS" >/dev/null; then
    printf 'converted header reached TurboHeader\n' >&2
    exit 1
fi
grep -Fx -- '--metadata' "$MOCK_IL2CPP_ARGS" >/dev/null
grep -Fx "$TMP/input files/global-metadata.dat" "$MOCK_IL2CPP_ARGS" >/dev/null
[[ -f "$TMP/output/com.example.game/ghidra_project/Il2CppAnalysis.gpr" ]]

printf 'headless workflow test passed\n'
