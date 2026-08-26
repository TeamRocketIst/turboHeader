#!/usr/bin/env python3
import argparse
from pathlib import Path, PurePosixPath
import stat
import zipfile

MODULE = "turboheader-ghidra-il2cpp"
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 25 * 1024 * 1024
ROOT_FILES = {
    "extension.properties",
    "Module.manifest",
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "README.md",
    "lib/turboheader-ghidra-il2cpp.jar",
    "ghidra_scripts/ImportIl2CppTypes.java",
    "ghidra_scripts/cpp2il_ghidra_export_editable.py",
}
PLATFORM_LIBRARIES = {
    "linux_x86_64": "libturboheader_il2cpp.so",
    "linux_aarch64": "libturboheader_il2cpp.so",
    "mac_x86_64": "libturboheader_il2cpp.dylib",
    "mac_aarch64": "libturboheader_il2cpp.dylib",
    "win_x86_64": "turboheader_il2cpp.dll",
}
DIRECTORIES = {"", "lib", "ghidra_scripts", "os"}
DIRECTORIES.update(f"os/{platform}" for platform in PLATFORM_LIBRARIES)


def archive_member(info: zipfile.ZipInfo) -> str:
    path = PurePosixPath(info.filename)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe archive member: {info.filename}")
    if not path.parts or path.parts[0] != MODULE:
        raise ValueError(f"archive member outside {MODULE}: {info.filename}")
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        raise ValueError(f"symbolic link is not allowed: {info.filename}")
    return "/".join(path.parts[1:])


def verify_archive(path: Path) -> None:
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError(f"extension archive is unexpectedly large: {path.stat().st_size} bytes")

    found = set()
    platforms = set()
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("extension archive contains duplicate members")
        expanded_size = sum(info.file_size for info in archive.infolist())
        if expanded_size > MAX_UNCOMPRESSED_BYTES:
            raise ValueError(f"extension archive expands to {expanded_size} bytes")
        for info in archive.infolist():
            relative = archive_member(info)
            if info.is_dir() and relative in DIRECTORIES:
                continue
            if info.is_dir():
                raise ValueError(f"unexpected extension directory: {info.filename}")
            if relative in ROOT_FILES:
                found.add(relative)
                continue
            parts = PurePosixPath(relative).parts
            if len(parts) == 3 and parts[0] == "os":
                platform = parts[1]
                if PLATFORM_LIBRARIES.get(platform) == parts[2]:
                    platforms.add(platform)
                    continue
            raise ValueError(f"unexpected extension member: {info.filename}")

    missing = ROOT_FILES - found
    if missing:
        raise ValueError(f"extension archive is missing required files: {sorted(missing)}")
    if len(platforms) != 1:
        raise ValueError(f"extension archive must contain one native platform, found {sorted(platforms)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    try:
        verify_archive(args.archive)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        raise SystemExit(str(error)) from error
    print(f"verified extension archive: {args.archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
