#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
PLATFORMS = {
    "linux_x86_64": ("libturboheader_il2cpp.so", "il2cpp_native_cli"),
    "linux_aarch64": ("libturboheader_il2cpp.so", "il2cpp_native_cli"),
    "mac_x86_64": ("libturboheader_il2cpp.dylib", "il2cpp_native_cli"),
    "mac_aarch64": ("libturboheader_il2cpp.dylib", "il2cpp_native_cli"),
    "win_x86_64": ("turboheader_il2cpp.dll", "il2cpp_native_cli.exe"),
}


def test_cli_builds_without_jni(tmp: Path):
    build = tmp / "no-jni"
    env = os.environ.copy()
    env["JAVA_HOME"] = str(tmp / "missing-jdk")
    subprocess.run(["cmake", "-S", str(ROOT / "native"), "-B", str(build),
                    "-DTURBOHEADER_BUILD_JNI=OFF"], check=True, env=env,
                   stdout=subprocess.DEVNULL)
    subprocess.run(["cmake", "--build", str(build), "--target", "il2cpp_native_cli"],
                   check=True, stdout=subprocess.DEVNULL)


def test_current_native(tmp: Path):
    build = ROOT / "native" / "build-clean"
    candidates = list(build.glob("libturboheader_il2cpp.*")) + list(build.glob("turboheader_il2cpp.dll"))
    if not candidates:
        raise AssertionError("run the normal native build before packaging tests")
    cli = build / ("il2cpp_native_cli.exe" if os.name == "nt" else "il2cpp_native_cli")
    machine = platform.machine().lower()
    arch = "aarch64" if machine in {"arm64", "aarch64"} else "x86_64"
    system = platform.system().lower()
    prefix = {"darwin": "mac", "windows": "win"}.get(system, system)
    platform_name = f"{prefix}_{arch}"
    command = [sys.executable, str(TOOLS / "verify_native.py"),
               "--library", str(candidates[0]), "--cli", str(cli),
               "--arch", arch, "--platform", platform_name,
               "--provenance", str(tmp / "provenance.json"),
               "--smoke-header", str(ROOT / "tests/fixtures/sample.h"),
               "--smoke-offsets", str(ROOT / "tests/fixtures/type_offsets.json")]
    if system == "linux":
        command += ["--glibc-max", "2.35"]
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL)


def test_deterministic_bundle(tmp: Path):
    arguments = []
    for name, (library, cli) in PLATFORMS.items():
        stage = tmp / name
        (stage / "lib").mkdir(parents=True)
        (stage / "bin").mkdir()
        (stage / "lib" / library).write_bytes(f"library:{name}".encode())
        (stage / "bin" / cli).write_bytes(f"cli:{name}".encode())
        library_path = stage / "lib" / library
        cli_path = stage / "bin" / cli
        provenance = {
            "platform": name,
            "files": {
                library: hashlib.sha256(library_path.read_bytes()).hexdigest(),
                cli: hashlib.sha256(cli_path.read_bytes()).hexdigest(),
            },
        }
        (stage / "provenance.json").write_text(json.dumps(provenance), encoding="utf-8")
        arguments += ["--artifact", f"{name}={stage}"]
    first = tmp / "first.zip"
    second = tmp / "second.zip"
    base = [sys.executable, str(TOOLS / "package_release.py")]
    subprocess.run(base + arguments + ["--output", str(first)], check=True,
                   stdout=subprocess.DEVNULL)
    reversed_arguments = []
    pairs = list(zip(arguments[::2], arguments[1::2]))
    for flag, value in reversed(pairs):
        reversed_arguments += [flag, value]
    subprocess.run(base + reversed_arguments + ["--output", str(second)], check=True,
                   stdout=subprocess.DEVNULL)
    assert hashlib.sha256(first.read_bytes()).digest() == hashlib.sha256(second.read_bytes()).digest()
    with zipfile.ZipFile(first) as archive:
        names = archive.namelist()
        assert "SHA256SUMS" in names
        assert len(names) == 16
        assert not any("build" in Path(name).parts or name.endswith((".pyc", ".i2gf")) for name in names)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        test_cli_builds_without_jni(temp)
        test_current_native(temp)
        test_deterministic_bundle(temp)
    print("packaging tests passed")
