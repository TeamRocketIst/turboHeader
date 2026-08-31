#!/usr/bin/env python3
"""Static invariants for the scheduled compatibility-release workflow."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/weekly-ghidra-release.yml"
PROPERTIES = ROOT / "extension.properties"
REAL_GHIDRA_TEST = ROOT / "tests/test_real_ghidra.sh"


def main() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    required = (
        'cron: "17 6 * * 1"',
        "workflow_dispatch:",
        "actions/checkout@v6",
        "actions/setup-java@v5",
        "actions/upload-artifact@v6",
        "actions/download-artifact@v6",
        "release-tests:",
        "release-clang-sanitizers:",
        "release-valgrind:",
        "Run complete release test suite",
        "CC=gcc ./tests/run_all.sh",
        "Run Clang ASan and UBSan tests",
        "python3 tests/test_sanitizers.py",
        "Run Valgrind tests",
        "python3 tests/test_valgrind.py",
        "TURBOHEADER_EXTENSION_ZIP",
        "TURBOHEADER_TEST_TEMP",
        "./tests/test_real_ghidra.sh",
        "needs: [discover, release-tests, release-clang-sanitizers, release-valgrind]",
        "needs: [discover, release-tests, release-clang-sanitizers, release-valgrind, build-desktop, build-linux]",
        'REQUESTED_TAG: ${{ inputs.ghidra_tag }}',
        'repos/NationalSecurityAgency/ghidra/releases/tags/$requested_tag',
        "repos/NationalSecurityAgency/ghidra/releases/latest",
        "ghidra_matrix",
        "fromJSON(needs.discover.outputs.ghidra_matrix)",
        "Ghidra distribution checksum mismatch",
        '$RUNNER_TEMP/turboheader-ghidra',
        "tools/verify_extension.py",
        "extension_archives=(dist/*.zip)",
        "linux_x86_64",
        "linux_aarch64",
        "mac_x86_64",
        "mac_aarch64",
        "win_x86_64",
        "ubuntu-24.04-arm",
        "macos-15-intel",
        "macos-15",
        "container: ubuntu:22.04",
        "shell: bash",
        "build-essential",
        "ninja-build",
        "cmake -S native -B build/native -G Ninja",
        "--glibc-max 2.35",
        "tools/verify_native.py",
        "sha256sum *.zip > SHA256SUMS",
        'manual_notes=".github/release-notes/v${EXTENSION_VERSION}.md"',
        'cat "$manual_notes" >>"$notes"',
        "gh release create",
        "gh release upload",
        "gh release edit",
        "gh release download",
        "Preserve existing compatibility archives",
        "cp --no-clobber",
        "--clobber",
        "--latest",
        "GH_REPO: ${{ github.repository }}",
    )
    missing = [value for value in required if value not in text]
    if missing:
        raise AssertionError(f"release workflow is missing invariants: {missing}")

    if text.count("platform:") != 5:
        raise AssertionError("release workflow must define exactly five native platforms")
    if 'release_tag="v${extension_version}"' not in text:
        raise AssertionError("release tag must identify TurboHeader independently of Ghidra")
    if 'release_tag="v${extension_version}-ghidra-' in text:
        raise AssertionError("release tag must not encode a Ghidra version")
    if text.count("fromJSON(needs.discover.outputs.ghidra_matrix)") != 2:
        raise AssertionError("desktop and Linux builds must use the supported-Ghidra matrix")
    if text.count("extension-${{ matrix.ghidra.version }}-${{ matrix.target.platform }}") != 2:
        raise AssertionError("artifacts must be unique for every Ghidra and platform pair")
    if text.count("tools/verify_extension.py") != 2:
        raise AssertionError("every platform extension build must verify its archive allowlist")
    if text.count("rm -rf dist") != 2:
        raise AssertionError("every platform build must clear stale extension archives")
    if text.count("extension_archives=(dist/*.zip)") != 2:
        raise AssertionError("every platform build must require one extension archive")
    if "head -n 1" in text:
        raise AssertionError("release inputs must reject ambiguous artifact matches")
    safety_needs = "needs: [discover, release-tests, release-clang-sanitizers, release-valgrind]"
    if text.count(safety_needs) != 2:
        raise AssertionError("every platform build must wait for all release safety tests")
    if text.count("TURBOHEADER_EXTENSION_ZIP") != 2:
        raise AssertionError("every platform build must test its exact packaged extension")
    if text.count("TURBOHEADER_TEST_TEMP") != 2:
        raise AssertionError("every platform build must isolate its headless test files")
    if text.count('chmod +x "$ghidra_dir/support/analyzeHeadless" "$ghidra_dir/support/launch.sh"') != 2:
        raise AssertionError("every Ghidra extraction must restore launcher permissions")

    publish = text.split("\n  publish:", 1)[1]
    checkout = publish.find("- uses: actions/checkout@v6")
    download = publish.find("- uses: actions/download-artifact@v6")
    if checkout < 0 or checkout > download:
        raise AssertionError("the publish job must check out versioned release notes")

    properties = PROPERTIES.read_text(encoding="utf-8").splitlines()
    version = next(line.split("=", 1)[1] for line in properties if line.startswith("version="))
    notes = ROOT / ".github/release-notes" / f"v{version}.md"
    if not notes.is_file() or not notes.read_text(encoding="utf-8").strip():
        raise AssertionError(f"release notes are missing for version {version}")

    real_ghidra_test = REAL_GHIDRA_TEST.read_text(encoding="utf-8")
    path_rules = (
        '${COMSPEC:-}',
        'cygpath -u "$COMSPEC"',
        'JAVA_TEST_BINARY',
        'JAVA_ROOT="$(cygpath -m "$ROOT")"',
        '-scriptPath "$JAVA_ROOT/ghidra_scripts;$JAVA_ROOT/tests/ghidra_scripts"',
    )
    for required_path_rule in path_rules:
        if required_path_rule not in real_ghidra_test:
            raise AssertionError(f"real-Ghidra test is missing path rule: {required_path_rule}")
    print("weekly release workflow checks passed")


if __name__ == "__main__":
    main()
