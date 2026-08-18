#!/usr/bin/env python3
"""Static invariants for the scheduled compatibility-release workflow."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/weekly-ghidra-release.yml"


def main() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    required = (
        'cron: "17 6 * * 1"',
        "workflow_dispatch:",
        "actions/checkout@v6",
        "actions/setup-java@v5",
        "actions/upload-artifact@v6",
        "actions/download-artifact@v6",
        "repos/NationalSecurityAgency/ghidra/releases/latest",
        "ghidra_digest",
        "Ghidra distribution checksum mismatch",
        '$RUNNER_TEMP/turboheader-ghidra',
        "extension archive is unexpectedly large",
        "extension archive contains Ghidra distribution files",
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
        "gh release create",
        "GH_REPO: ${{ github.repository }}",
    )
    missing = [value for value in required if value not in text]
    if missing:
        raise AssertionError(f"release workflow is missing invariants: {missing}")

    if text.count("platform:") != 5:
        raise AssertionError("release workflow must define exactly five native platforms")
    if "git/ref/tags/$release_tag" not in text:
        raise AssertionError("release workflow must not overwrite an existing compatibility tag")
    print("weekly release workflow checks passed")


if __name__ == "__main__":
    main()
