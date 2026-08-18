#!/usr/bin/env python3
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = Path(os.environ.get("TURBOHEADER_VALGRIND_BUILD_DIR",
                                ROOT / "native" / "build-valgrind"))
CLI = BUILD_DIR / "il2cpp_native_cli"
VALGRIND = shutil.which("valgrind")

if VALGRIND is None:
    raise SystemExit("valgrind is required")
if not CLI.is_file():
    raise SystemExit(f"native CLI does not exist: {CLI}")

BASE = [
    VALGRIND,
    "--tool=memcheck",
    "--leak-check=full",
    "--show-leak-kinds=all",
    "--errors-for-leak-kinds=definite,indirect,possible",
    "--track-origins=yes",
    "--track-fds=yes",
    "--error-exitcode=99",
]


def run_case(arguments, expected):
    result = subprocess.run(BASE + [str(CLI)] + [str(value) for value in arguments],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 99:
        raise SystemExit(result.stderr.decode("utf-8", "replace"))
    if result.returncode != expected:
        raise SystemExit(
            f"unexpected exit {result.returncode}, expected {expected}\n" +
            result.stderr.decode("utf-8", "replace"))


with tempfile.TemporaryDirectory() as temporary:
    temporary = Path(temporary)
    run_case([
        ROOT / "tests/fixtures/sample.h",
        ROOT / "tests/fixtures/type_offsets.json",
        temporary / "valid.i2gf",
        "8",
    ], 0)

    malformed_header = temporary / "malformed.h"
    malformed_header.write_text("struct Broken_Fields { struct { int value; ")
    malformed_offsets = temporary / "malformed.json"
    malformed_offsets.write_text('{"types":{"Broken_Fields":{"fields":{"value":16}}}}')
    run_case([malformed_header, malformed_offsets, temporary / "malformed.i2gf", "8"], 0)

    invalid_offsets = temporary / "invalid.json"
    invalid_offsets.write_text('{"types":{')
    run_case([
        ROOT / "tests/fixtures/sample.h",
        invalid_offsets,
        temporary / "invalid.i2gf",
        "8",
    ], 1)
    deep_offsets = temporary / "deep.json"
    deep_offsets.write_text('{"ignored":' + '[' * 1000 + '0' + ']' * 1000 + ',"types":{}}')
    run_case([
        ROOT / "tests/fixtures/sample.h",
        deep_offsets,
        temporary / "deep.i2gf",
        "8",
    ], 1)
    run_case([
        ROOT / "tests/fixtures/sample.h",
        ROOT / "tests/fixtures/type_offsets.json",
        temporary / "bad-pointer.i2gf",
        "7",
    ], 1)

    output_directory = temporary / "output-directory"
    output_directory.mkdir()
    run_case([
        ROOT / "tests/fixtures/sample.h",
        ROOT / "tests/fixtures/type_offsets.json",
        output_directory,
        "8",
    ], 1)
    run_case([temporary / "missing.h", "-", temporary / "missing.i2gf", "8"], 1)

print("Valgrind valid, malformed, and error-path cases passed")
