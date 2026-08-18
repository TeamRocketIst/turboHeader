#!/usr/bin/env python3
import json
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = Path(os.environ.get("TURBOHEADER_SANITIZER_BUILD_DIR",
                                ROOT / "native" / "build-sanitize"))
CLI = BUILD_DIR / "il2cpp_native_cli"
RNG = random.Random(0x51A7)
detect_leaks = "0" if sys.platform == "darwin" else "1"
ENV = dict(os.environ, ASAN_OPTIONS=f"detect_leaks={detect_leaks}:abort_on_error=1",
           UBSAN_OPTIONS="halt_on_error=1")

# First run the complete valid fixture under ASan/UBSan.
with tempfile.TemporaryDirectory() as td:
    out = Path(td) / "ok.i2gf"
    subprocess.run([str(CLI), str(ROOT / "tests/fixtures/sample.h"),
                    str(ROOT / "tests/fixtures/type_offsets.json"), str(out), "8"],
                   env=ENV, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# Recursive value layout can grow and relocate the layout-record vector. Keep
# enough nested records to cross the initial capacity while callers are active.
with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    header = td / "nested.h"
    out = td / "nested.i2gf"
    definitions = ["struct Nested11_Fields { int32_t value; };"]
    for index in range(10, -1, -1):
        definitions.append(
            f"struct Nested{index}_Fields {{ struct Nested{index + 1}_Fields value; }};"
        )
    definitions.extend([
        "struct NestedRoot_c { void *unused; };",
        "struct NestedRoot_Fields { struct Nested0_Fields value; };",
        "struct NestedRoot_o { struct NestedRoot_c *klass; void *monitor; "
        "struct NestedRoot_Fields fields; };",
    ])
    header.write_text("\n".join(definitions))
    subprocess.run([str(CLI), str(header), "-", str(out), "8"],
                   env=ENV, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# The native parser runs in Ghidra's JVM. A deeply nested ignored JSON value must be rejected at the
# configured boundary instead of recursively exhausting the process stack.
with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    offsets = td / "deep.json"
    out = td / "deep.i2gf"
    offsets.write_text('{"ignored":' + '[' * 100_000 + '0' + ']' * 100_000 + ',"types":{}}')
    result = subprocess.run(
        [str(CLI), str(ROOT / "tests/fixtures/sample.h"), str(offsets), str(out), "8"],
        env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode != 1 or b"nesting exceeds limit" not in result.stderr:
        raise SystemExit("deep JSON did not fail closed\n" +
                         result.stderr.decode("utf-8", "replace"))

# Then exercise malformed lexing, comments, nesting and offset feeds. Parse errors are fine;
# sanitizer diagnostics or signal exits are not.
for i in range(400):
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        h = td / "fuzz.h"
        o = td / ("fuzz.json" if i % 2 else "fuzz.cs")
        out = td / "out.i2gf"
        alphabet = "struct{}_Fields_o;:*[]()/\\\n\t abcXYZ0123456789/*"
        h.write_text("".join(RNG.choice(alphabet) for _ in range(RNG.randint(0, 5000))),
                     errors="ignore")
        if o.suffix == ".json":
            if i % 4 == 1:
                names = {f"T{n}": {"fields": {f"f{k}": RNG.randrange(0, 512)
                                                  for k in range(RNG.randrange(0, 8))}}
                         for n in range(RNG.randrange(0, 20))}
                o.write_text(json.dumps({"types": names}))
            else:
                o.write_text("".join(RNG.choice('{}[],:\"0123456789 abc')
                                     for _ in range(RNG.randint(0, 3000))))
        else:
            o.write_text("".join(RNG.choice(alphabet) for _ in range(RNG.randint(0, 3000))))
        result = subprocess.run([str(CLI), str(h), str(o), str(out), "8"], env=ENV,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode not in (0, 1):
            raise SystemExit(f"iteration {i}: abnormal exit {result.returncode}\n" +
                             result.stderr.decode("utf-8", "replace"))
        stderr = result.stderr.decode("utf-8", "replace")
        if "AddressSanitizer" in stderr or "runtime error:" in stderr:
            raise SystemExit(f"iteration {i}: sanitizer report\n{stderr}")
print("ASan/UBSan fixture + 400 malformed-input cases passed")
