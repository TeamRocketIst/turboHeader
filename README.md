# turboHeader

turboHeader imports IL2CPP types and method signatures into Ghidra, then exports selected classes as decompiled C++.

After installing TurboHeader, use the
[il2cpp-ghidrah wrapper](https://github.com/TeamRocketIst/il2cpp-ghidrah) for the end-to-end command-line workflow. It runs the import and export as separate `analyzeHeadless` processes using Java entry points and validated request manifests.

## Requirements

- Ghidra 12+
- Java 21
- CMake 3.20+
- A C11 compiler

## Install

Set `GHIDRA_INSTALL_DIR` to the directory containing `ghidraRun` and `Ghidra/application.properties`.

For a Ghidra archive extracted on Linux:

```sh
export GHIDRA_INSTALL_DIR="$HOME/ghidra_12.1.2_PUBLIC"
```

For Ghidra installed with Homebrew on macOS:

```sh
export GHIDRA_INSTALL_DIR="$(brew --prefix ghidra)/libexec"
```

Add the appropriate `export` command to `~/.zshrc`, `~/.bashrc`, or `~/.bash_profile` to keep it across terminal sessions.

Each [TurboHeader release](https://github.com/TeamRocketIst/turboHeader/releases) groups all supported Ghidra
builds together. Download the archive containing your exact Ghidra version and platform, then extract it directly
into Ghidra:

```sh
TURBOHEADER_ZIP=/path/to/downloaded/turboheader-release.zip
unzip "$TURBOHEADER_ZIP" -d "$GHIDRA_INSTALL_DIR/Ghidra/Extensions"
```

Linux archives end in `linux_x86_64` or `linux_aarch64`. macOS archives end in `mac_x86_64` or `mac_aarch64`.

The official Ghidra archive does not include Linux ARM64 native tools. Build them once after extracting Ghidra:

```sh
cd "$GHIDRA_INSTALL_DIR/support/gradle"
./gradlew buildNatives
```

To build the extension locally instead:

```sh
./gradlew --no-daemon buildExtension
unzip dist/ghidra_12.1.2_PUBLIC_20260815_turboheader-ghidra-il2cpp.zip \
  -d "$GHIDRA_INSTALL_DIR/Ghidra/Extensions"
```

Use the archive name produced by your build.

Restart Ghidra after installing or replacing the extension.

## Input files

- `libil2cpp.so`: native Unity IL2CPP binary.
- `il2cpp.h`: generated IL2CPP type declarations.
- `dump.cs`: field-offset data commonly produced by Il2CppDumper.
- `type_offsets.json`: optional precise field-offset data. The default workflow that generates this file will be
  released separately.
- `script.json`: string literals, metadata slots, method addresses, names, signatures, and assembly information.
- `DiffableCs`: Cpp2IL class tree used to select and organize exported methods.

Use files generated from the same application. Pass `-` when no offset file is available; layouts will then be
inferred from `il2cpp.h` and may be less accurate.

The pointer size is detected automatically from the `libil2cpp.so` program imported by Ghidra.

## Run

Install the wrapper in a virtual environment after installing TurboHeader:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install il2cpp-ghidrah
il2cpp-ghidrah doctor --probe
```

Then run the default TurboHeader workflow:

```sh
il2cpp-ghidrah run /path/to/libil2cpp.so \
  -M /path/to/global-metadata.dat \
  -g dumper \
  -u 2022.3.62f3 \
  -o output
```

Replace the Unity version with the application's exact version. See the wrapper's
[README](https://github.com/TeamRocketIst/il2cpp-ghidrah#readme) for input formats,
selection modes and advanced options.

## Tests

```sh
./tests/run_all.sh
```

The repository contains only small synthetic fixtures. It does not include application binaries or generated data.

## Acknowledgments

This project was developed together with Antonio Freire ([TSelecta](https://github.com/TSelecta)). His work and contributions were essential to making it possible.

## License

GNU LGPL v3. See `LICENSE` and `THIRD_PARTY_NOTICES.md`.
