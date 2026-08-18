# turboHeader

turboHeader imports IL2CPP types and method signatures into Ghidra, then exports selected classes as decompiled C++.

The workflow has two steps, in this order:

1. Import the IL2CPP data into a Ghidra project.
2. Run the exporter using that same project.

## Requirements

- Ghidra 12+
- Java 21
- CMake 3.20+
- A C11 compiler

## Build and install

```sh
export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.2_PUBLIC
./gradlew --no-daemon buildExtension
```

Install the ZIP from `dist/` using **File -> Install Extensions**, or extract it manually:

```sh
unzip dist/ghidra_12.1.2_PUBLIC_20260815_turboheader-ghidra-il2cpp.zip \
  -d "$GHIDRA_INSTALL_DIR/Ghidra/Extensions"
```

Use the archive name produced by your build.

Restart Ghidra after installing or replacing the extension.

## Input files

- `libil2cpp.so`: native Unity IL2CPP binary.
- `il2cpp.h`: generated IL2CPP type declarations.
- `dump.cs`: field-offset data commonly produced by Il2CppDumper.
- `type_offsets.json`: precise field-offset data produced by `il2cpp_net`.
- `script.json`: string literals, metadata slots, method addresses, names, signatures, and assembly information.
- `DiffableCs`: Cpp2IL class tree used to select and organize exported methods.

Use files generated from the same application. Pass `-` when no offset file is available; layouts will then be
inferred from `il2cpp.h` and may be less accurate.

The pointer size is detected automatically from the `libil2cpp.so` program imported by Ghidra.

## 1. Import

Run this first:

```sh
$GHIDRA_INSTALL_DIR/support/analyzeHeadless \
  projects game \
  -import /path/to/libil2cpp.so \
  -noanalysis \
  -postScript ImportIl2CppTypes.java \
  /path/to/il2cpp.h \
  /path/to/dump.cs \
  /path/to/script.json \
  allow-inferred
```

This example uses the files produced by Il2CppDumper. If you use `il2cpp_net`, replace `dump.cs` with
`type_offsets.json` and use `require-external-offsets` for stricter field layouts.

For header-only import, use:

```text
/path/to/il2cpp.h - /path/to/script.json allow-inferred
```

The layout policy can be `allow-inferred`, `require-external-offsets`, or `require-authoritative`.

## 2. Export

After the import succeeds, run the exporter with the same project directory and project name:

```sh
$GHIDRA_INSTALL_DIR/support/analyzeHeadless \
  projects game \
  -process libil2cpp.so \
  -noanalysis \
  -postScript cpp2il_ghidra_export_editable.py \
  /path/to/DiffableCs \
  /path/to/out \
  blacklist \
  /path/to/framework_ignore.txt \
  --decompile-jobs 8
```

The selection mode can be `whitelist`, `blacklist`, or `all`.

On AArch64, non-returning helpers are detected automatically. A matching seed file can also be supplied with
`--noreturn-seeds /path/to/noreturn-seeds.txt`.

Eight decompiler workers were the fastest tested setting on the 12-core development machine. Values up to 12 are
supported for experimentation.

## Tests

```sh
./tests/run_all.sh
```

The repository contains only small synthetic fixtures. It does not include application binaries or generated data.

## Acknowledgments

This project was developed together with Antonio Freire (TSelecta). His work and contributions were essential to making it possible.

## License

GNU LGPL v3. See `LICENSE` and `THIRD_PARTY_NOTICES.md`.
