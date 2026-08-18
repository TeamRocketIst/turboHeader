#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage: import_headless.sh <libil2cpp.so> <global-metadata.dat> <package-name> [unity-version]

Environment:
  GHIDRA_INSTALL_DIR      Ghidra installation containing support/analyzeHeadless
  IL2CPP_BIN             il2cpp executable (default: il2cpp)
  TURBOHEADER_OUTPUT_ROOT  output parent directory (default: ./output)
EOF
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

absolute_file() {
    local path="$1"
    local directory
    directory="$(cd "$(dirname "$path")" && pwd -P)"
    printf '%s/%s\n' "$directory" "$(basename "$path")"
}

[[ $# -eq 3 || $# -eq 4 ]] || { usage; exit 2; }

lib="$(absolute_file "$1")"
metadata="$(absolute_file "$2")"
package_name="$3"
unity_version="${4:-2022.3.62f2}"

[[ -f "$lib" ]] || fail "libil2cpp binary not found: $lib"
[[ -f "$metadata" ]] || fail "metadata file not found: $metadata"
[[ "$package_name" =~ ^[A-Za-z0-9._-]+$ ]] || fail "invalid package name: $package_name"

ghidra_install_dir="${GHIDRA_INSTALL_DIR:-}"
[[ -n "$ghidra_install_dir" ]] || fail "GHIDRA_INSTALL_DIR is not set"
headless="$ghidra_install_dir/support/analyzeHeadless"
[[ -x "$headless" ]] || fail "analyzeHeadless not found: $headless"

il2cpp_bin="${IL2CPP_BIN:-il2cpp}"
command -v "$il2cpp_bin" >/dev/null 2>&1 || fail "il2cpp executable not found: $il2cpp_bin"

output_root="${TURBOHEADER_OUTPUT_ROOT:-$PWD/output}"
destination="$output_root/$package_name"
generated="$destination/out_il2"
project_dir="$destination/ghidra_project"
project_name="Il2CppAnalysis"

# These directories contain only reproducible output for this package. Starting
# clean prevents a different binary or an interrupted run from being reused.
rm -rf "$generated" "$project_dir"
mkdir -p "$generated" "$project_dir"

printf 'Generating IL2CPP metadata artefacts for %s...\n' "$package_name"
"$il2cpp_bin" gen "$lib" "$generated" \
    --metadata "$metadata" \
    --unity "$unity_version"

header="$generated/il2cpp.h"
offsets="$generated/type_offsets.json"
script="$generated/script.json"
for required in "$header" "$offsets" "$script"; do
    [[ -s "$required" ]] || fail "generator did not produce: $required"
done

printf 'Importing raw il2cpp.h into Ghidra...\n'
import_log="$destination/ghidra-import.log"
"$headless" "$project_dir" "$project_name" \
    -import "$lib" \
    -noanalysis \
    -postScript ImportIl2CppTypes.java "$header" "$offsets" "$script" \
    require-external-offsets \
    2>&1 | tee "$import_log"

if grep -Fq 'SCRIPT ERROR' "$import_log" || grep -Fq 'Abort due to Headless analyzer error' "$import_log"; then
    fail "Ghidra reported a script error; see $import_log"
fi
grep -Fq 'TurboHeader methods:' "$import_log" ||
    fail "Ghidra did not report method import statistics; see $import_log"
grep -Eq 'TurboHeader methods:.*, 0 failed in ' "$import_log" ||
    fail "one or more method signatures were not applied; see $import_log"
grep -Fq 'TurboHeader metadata:' "$import_log" ||
    fail "Ghidra did not report metadata import statistics; see $import_log"
grep -Eq 'TurboHeader metadata:.*, 0 failed in ' "$import_log" ||
    fail "one or more metadata slots were not applied; see $import_log"
grep -Fq 'TurboHeader layout evidence: source=TYPE_OFFSETS_JSON' "$import_log" ||
    fail "Ghidra did not identify the generated type_offsets.json source; see $import_log"

printf 'TurboHeader project written to %s\n' "$project_dir/$project_name.gpr"
