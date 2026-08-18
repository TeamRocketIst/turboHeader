#!/usr/bin/env python3
"""Create a deterministic native bundle from verified CMake install trees."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import zipfile

PLATFORMS = {
    "linux_x86_64": ("libturboheader_il2cpp.so", "il2cpp_native_cli"),
    "linux_aarch64": ("libturboheader_il2cpp.so", "il2cpp_native_cli"),
    "mac_x86_64": ("libturboheader_il2cpp.dylib", "il2cpp_native_cli"),
    "mac_aarch64": ("libturboheader_il2cpp.dylib", "il2cpp_native_cli"),
    "win_x86_64": ("turboheader_il2cpp.dll", "il2cpp_native_cli.exe"),
}
FORBIDDEN = {"build", ".gradle", "__pycache__", ".pyc", ".i2gf"}


def find_file(root: Path, name: str) -> Path:
    matches = [path for path in root.rglob(name) if path.is_file()]
    if len(matches) != 1:
        raise ValueError(f"expected one {name} under {root}, found {len(matches)}")
    return matches[0]


def zip_info(name: str, executable: bool) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    mode = 0o755 if executable else 0o644
    info.external_attr = (stat.S_IFREG | mode) << 16
    return info


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", action="append", required=True,
                        help="platform=verified-install-directory")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    files = {}
    provenance = {}
    seen = set()
    for value in args.artifact:
        platform, separator, root_text = value.partition("=")
        if not separator or platform not in PLATFORMS or platform in seen:
            raise SystemExit(f"invalid or duplicate artifact: {value}")
        seen.add(platform)
        root = Path(root_text)
        library_name, cli_name = PLATFORMS[platform]
        library = find_file(root, library_name)
        cli = find_file(root, cli_name)
        provenance_file = find_file(root, "provenance.json")
        provenance[platform] = json.loads(provenance_file.read_text(encoding="utf-8"))
        if provenance[platform].get("platform") != platform:
            raise ValueError(f"provenance platform mismatch for {platform}")
        expected_hashes = provenance[platform].get("files", {})
        for artifact in (library, cli):
            actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
            if expected_hashes.get(artifact.name) != actual:
                raise ValueError(f"provenance hash mismatch for {platform}/{artifact.name}")
        files[f"os/{platform}/{library_name}"] = (library, False)
        files[f"bin/{platform}/{cli_name}"] = (cli, True)
        files[f"provenance/{platform}.json"] = (provenance_file, False)

    if seen != set(PLATFORMS):
        raise SystemExit(f"incomplete platform set: missing {sorted(set(PLATFORMS) - seen)}")

    checksums = []
    for name, (path, _) in sorted(files.items()):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        checksums.append(f"{digest}  {name}")
    manifest = ("\n".join(checksums) + "\n").encode()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, "w") as archive:
        for name, (path, executable) in sorted(files.items()):
            archive.writestr(zip_info(name, executable), path.read_bytes())
        archive.writestr(zip_info("SHA256SUMS", False), manifest)

    with zipfile.ZipFile(args.output) as archive:
        names = archive.namelist()
        for name in names:
            parts = PurePosixPath(name).parts
            if any(part in FORBIDDEN or part.endswith((".pyc", ".i2gf")) for part in parts):
                raise SystemExit(f"forbidden archive member: {name}")
        if len(names) != len(set(names)):
            raise SystemExit("duplicate archive members")
    print(f"wrote {args.output} ({len(files)} files plus checksums)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
