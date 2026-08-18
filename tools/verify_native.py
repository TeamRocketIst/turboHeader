#!/usr/bin/env python3
"""Verify a release native library without relying on platform-specific tools."""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

JNI_EXPORTS = (
    "Java_turboheader_il2cpp_NativeParser_apiVersion0",
    "Java_turboheader_il2cpp_NativeParser_parse0",
)


def binary_arch(path: Path) -> str:
    data = path.read_bytes()
    if data[:4] == b"\x7fELF":
        if data[4] != 2 or data[5] != 1:
            raise ValueError("release ELF must be little-endian 64-bit")
        machine = struct.unpack_from("<H", data, 18)[0]
        return {62: "x86_64", 183: "aarch64"}.get(machine, f"elf-{machine}")
    if data[:4] == b"\xcf\xfa\xed\xfe":
        cpu = struct.unpack_from("<I", data, 4)[0]
        return {0x01000007: "x86_64", 0x0100000C: "aarch64"}.get(cpu, f"macho-{cpu}")
    if data[:2] == b"MZ":
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise ValueError("invalid PE header")
        machine = struct.unpack_from("<H", data, pe + 4)[0]
        return {0x8664: "x86_64", 0xAA64: "aarch64"}.get(machine, f"pe-{machine}")
    raise ValueError("unsupported native-library format")


def max_glibc(path: Path):
    versions = {(int(a), int(b)) for a, b in re.findall(rb"GLIBC_(\d+)\.(\d+)", path.read_bytes())}
    return max(versions) if versions else None


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument("--cli", required=True, type=Path)
    parser.add_argument("--arch", required=True, choices=("x86_64", "aarch64"))
    parser.add_argument("--platform", required=True)
    parser.add_argument("--glibc-max")
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--smoke-header", type=Path)
    parser.add_argument("--smoke-offsets", type=Path)
    args = parser.parse_args()

    for path in (args.library, args.cli):
        if not path.is_file() or path.stat().st_size == 0:
            raise SystemExit(f"missing release file: {path}")
    actual_arch = binary_arch(args.library)
    cli_arch = binary_arch(args.cli)
    if actual_arch != args.arch or cli_arch != args.arch:
        raise SystemExit(
            f"architecture mismatch: expected {args.arch}, library={actual_arch}, cli={cli_arch}")

    library = ctypes.CDLL(str(args.library.resolve()))
    for export in JNI_EXPORTS:
        if not getattr(library, export, None):
            raise SystemExit(f"missing JNI export: {export}")
    glibc_versions = [version for version in (max_glibc(args.library), max_glibc(args.cli)) if version]
    glibc = max(glibc_versions) if glibc_versions else None
    if args.glibc_max:
        limit = tuple(map(int, args.glibc_max.split(".", 1)))
        if glibc and glibc > limit:
            raise SystemExit(f"GLIBC_{glibc[0]}.{glibc[1]} exceeds policy {args.glibc_max}")

    if bool(args.smoke_header) != bool(args.smoke_offsets):
        raise SystemExit("--smoke-header and --smoke-offsets must be used together")
    if args.smoke_header:
        with tempfile.TemporaryDirectory() as directory:
            model = Path(directory) / "smoke.i2gf"
            subprocess.run([str(args.cli.resolve()), str(args.smoke_header.resolve()),
                            str(args.smoke_offsets.resolve()), str(model), "8"],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            data = model.read_bytes()
            if len(data) < 48 or data[:4] != b"I2GF" or struct.unpack_from("<I", data, 4)[0] != 3 or \
                    struct.unpack_from("<I", data, 8)[0] != 8 or \
                    struct.unpack_from("<I", data, 12)[0] == 0 or \
                    sum(struct.unpack_from("<5I", data, 20)) != struct.unpack_from("<I", data, 16)[0] or \
                    struct.unpack_from("<I", data, 40)[0] != 2 or \
                    struct.unpack_from("<I", data, 44)[0] != 3:
                raise SystemExit("native CLI smoke test produced an invalid model")

    record = {
        "platform": args.platform,
        "architecture": actual_arch,
        "jniExports": JNI_EXPORTS,
        "glibcMaximum": ".".join(map(str, glibc)) if glibc else None,
        "sourceRevision": os.environ.get("GITHUB_SHA", "unknown"),
        "workflowRun": os.environ.get("GITHUB_RUN_ID", "local"),
        "files": {
            args.library.name: sha256(args.library),
            args.cli.name: sha256(args.cli),
        },
    }
    if args.provenance:
        args.provenance.parent.mkdir(parents=True, exist_ok=True)
        args.provenance.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
