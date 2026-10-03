#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/compatibility-check.yml"
ACTION = ROOT / ".github/actions/check-ghidra-platform/action.yml"


def run_script(text, name):
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == "- name: " + name)
    indent = len(lines[start]) - len(lines[start].lstrip()) + 2
    start = next(i for i in range(start + 1, len(lines))
                 if lines[i] == " " * indent + "run: |")
    body = []
    for line in lines[start + 1:]:
        if line and not line.startswith(" " * (indent + 2)):
            break
        body.append(line[indent + 2:])
    return "\n".join(body) + "\n"


def release():
    name = "ghidra_12.0.0_PUBLIC_20260101.zip"
    return {
        "tag_name": "Ghidra_12.0.0_build",
        "assets": [{
            "name": name,
            "browser_download_url": "https://github.com/NationalSecurityAgency/ghidra/releases/"
                                    "download/Ghidra_12.0.0_build/" + name,
            "digest": "sha256:" + "a" * 64,
        }],
    }


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = WORKFLOW.read_text(encoding="utf-8")
        self.action = ACTION.read_text(encoding="utf-8")

    def test_manual_read_only(self):
        self.assertIn('"on":\n  workflow_dispatch:', self.workflow)
        self.assertIn("permissions:\n  contents: read", self.workflow)
        for text in (self.workflow, self.action):
            self.assertNotRegex(text, r"\b(?:schedule|push|pull_request|publish):")
            self.assertNotIn("contents: write", text)
            self.assertNotIn("id-token:", text)
            self.assertNotRegex(text, r"\bgh\s+release\b|\bgit\s+(?:push|tag)\b")
            self.assertNotIn("continue-on-error", text)
            self.assertNotIn("release-notes", text)

    def test_pinned_actions(self):
        uses = re.findall(r"uses: ([^\s]+)", self.workflow)
        external = [value for value in uses if not value.startswith("./")]
        self.assertTrue(external)
        for value in external:
            self.assertRegex(value, r"^actions/[a-z-]+@[0-9a-f]{40}$")
        self.assertEqual(self.workflow.count("persist-credentials: false"), 3)

    def test_all_platforms_and_time_limits(self):
        platforms = re.findall(r"^\s+- platform: (\w+)$", self.workflow, re.MULTILINE)
        self.assertCountEqual(platforms, ["win_x86_64", "mac_x86_64", "mac_aarch64",
                                         "linux_x86_64", "linux_aarch64"])
        self.assertIn("container: ubuntu:22.04", self.workflow)
        self.assertIn("os: ubuntu-24.04-arm", self.workflow)
        self.assertIn("os: macos-15-intel", self.workflow)
        self.assertEqual(self.workflow.count("timeout-minutes:"), 3)
        self.assertEqual(self.workflow.count("fail-fast: false"), 2)
        self.assertEqual(self.workflow.count("uses: ./.github/actions/check-ghidra-platform"), 2)

    def test_exact_archive_and_portability_gate(self):
        for required in ("--glibc-max 2.35", "tools/verify_native.py", "tools/verify_extension.py",
                         "TURBOHEADER_EXTENSION_ZIP", "bash tests/test_real_ghidra.sh",
                         ":Decompiler:buildNatives", "TURBOHEADER_WARNINGS_AS_ERRORS=ON"):
            self.assertIn(required, self.action)
        self.assertIn('[[ "${#archives[@]}" -eq 1', self.action)
        self.assertEqual(self.action.count("set -euo pipefail"), 4)
        self.assertNotIn("./tests/run_all.sh", self.action)
        self.assertNotIn("tests/test_release_workflow.py", self.action)
        self.assertIn('cygpath -m "$download_dir"', self.action)
        self.assertIn('cygpath -m "$ghidra_dir"', self.action)

    def test_inputs_are_not_interpolated_into_shell(self):
        for text, names in ((self.workflow, ["Resolve Ghidra release"]),
                            (self.action, ["Download and verify Ghidra", "Prepare Ghidra decompiler",
                                           "Build and verify native library", "Package and test extension"])):
            for name in names:
                self.assertNotIn("${{", run_script(text, name))
        self.assertIn("REQUESTED_TAG: ${{ inputs.ghidra_tag }}", self.workflow)


@unittest.skipUnless(shutil.which("bash") and shutil.which("jq"), "bash and jq are required")
class ReleaseResolverTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.output = self.root / "output"
        self.output.write_text("sentinel\n", encoding="utf-8")
        self.gh_log = self.root / "gh.args"
        gh = self.bin / "gh"
        gh.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, sys\n"
            "pathlib.Path(os.environ['MOCK_GH_ARGS']).write_text('\\n'.join(sys.argv[1:]))\n"
            "print(os.environ['MOCK_GH_RELEASE'])\n", encoding="utf-8")
        gh.chmod(0o700)
        self.script = run_script(WORKFLOW.read_text(encoding="utf-8"), "Resolve Ghidra release")

    def tearDown(self):
        self.folder.cleanup()

    def resolve(self, tag, data):
        env = os.environ.copy()
        env.update(PATH=str(self.bin) + os.pathsep + env["PATH"], REQUESTED_TAG=tag,
                   GITHUB_OUTPUT=str(self.output), MOCK_GH_ARGS=str(self.gh_log),
                   MOCK_GH_RELEASE=json.dumps(data))
        return subprocess.run(["bash", "-c", self.script], env=env, cwd=self.root,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)

    def rejected(self, tag, data):
        result = self.resolve(tag, data)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "sentinel\n")
        self.assertFalse((self.root / "injected").exists())

    def test_explicit_release(self):
        result = self.resolve("Ghidra_12.0.0_build", release())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("version=12.0.0\n", self.output.read_text(encoding="utf-8"))
        self.assertEqual(self.gh_log.read_text(), "api\nrepos/NationalSecurityAgency/ghidra/releases/tags/Ghidra_12.0.0_build")

    def test_latest_release(self):
        result = self.resolve("", release())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.gh_log.read_text(), "api\nrepos/NationalSecurityAgency/ghidra/releases/latest")

    def test_invalid_tags_do_not_reach_api(self):
        for tag in ("../main", "Ghidra_12.0.0_build; touch injected",
                    "Ghidra_12.0.0_build\nextra", "$(touch injected)", "Ghidra_12x0x0_build"):
            with self.subTest(tag=tag):
                self.rejected(tag, release())
                self.assertFalse(self.gh_log.exists())

    def test_wrong_release_tag(self):
        data = release()
        data["tag_name"] = "Ghidra_12.0.1_build"
        self.rejected("Ghidra_12.0.0_build", data)

    def test_missing_or_ambiguous_assets(self):
        for assets in ([], None, [release()["assets"][0]] * 2):
            with self.subTest(assets=assets):
                data = release()
                data["assets"] = assets
                self.rejected("Ghidra_12.0.0_build", data)

    def test_invalid_asset_names(self):
        for name in ("ghidra_12.0.0_PUBLIC_../20260101.zip",
                     "ghidra_12.0.0_PUBLIC_20260101\nextra.zip"):
            with self.subTest(name=name):
                data = release()
                data["assets"][0]["name"] = name
                self.rejected("Ghidra_12.0.0_build", data)

    def test_url_must_match_official_asset(self):
        for url in ("https://example.invalid/archive.zip",
                    release()["assets"][0]["browser_download_url"] + "?extra=1"):
            with self.subTest(url=url):
                data = release()
                data["assets"][0]["browser_download_url"] = url
                self.rejected("Ghidra_12.0.0_build", data)

    def test_digest_is_required(self):
        for digest in ("", None, "sha512:" + "a" * 64, "sha256:" + "g" * 64,
                       "sha256:" + "a" * 64 + "\nextra"):
            with self.subTest(digest=digest):
                data = release()
                data["assets"][0]["digest"] = digest
                self.rejected("Ghidra_12.0.0_build", data)


@unittest.skipUnless(shutil.which("bash") and shutil.which("unzip"), "bash and unzip are required")
class DistributionTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        curl = self.bin / "curl"
        curl.write_text(
            "#!/usr/bin/env python3\n"
            "import os, shutil, sys\n"
            "shutil.copyfile(os.environ['MOCK_ZIP'], sys.argv[sys.argv.index('--output') + 1])\n",
            encoding="utf-8")
        curl.chmod(0o700)
        self.archive = self.root / "fixture.zip"
        self.output = self.root / "environment"
        self.output.write_text("sentinel\n", encoding="utf-8")
        self.outside = self.root / "outside"
        self.outside.write_text("unchanged", encoding="utf-8")
        self.script = run_script(ACTION.read_text(encoding="utf-8"), "Download and verify Ghidra")

    def tearDown(self):
        self.folder.cleanup()

    def fixture(self, extra=None):
        prefix = "ghidra_12.0.0_PUBLIC/"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.archive, "w") as archive:
                archive.writestr(prefix + "Ghidra/application.properties", "application.version=12.0.0\n")
                for name in ("buildExtension.gradle", "analyzeHeadless", "launch.sh"):
                    archive.writestr(prefix + "support/" + name, "")
                if isinstance(extra, zipfile.ZipInfo):
                    archive.writestr(extra, "outside")
                elif extra:
                    archive.writestr(extra, "outside")

    def download(self, digest=None, system="Linux"):
        if digest is None:
            digest = "sha256:" + hashlib.sha256(self.archive.read_bytes()).hexdigest()
        env = os.environ.copy()
        env.update(PATH=str(self.bin) + os.pathsep + env["PATH"], RUNNER_TEMP=str(self.root),
                   RUNNER_OS=system, GITHUB_ENV=str(self.output), MOCK_ZIP=str(self.archive),
                   GHIDRA_VERSION="12.0.0", GHIDRA_DIGEST=digest,
                   GHIDRA_URL=release()["assets"][0]["browser_download_url"])
        return subprocess.run(["bash", "-c", self.script], env=env, cwd=self.root,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)

    def rejected(self):
        result = self.download()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "sentinel\n")
        self.assertEqual(self.outside.read_text(encoding="utf-8"), "unchanged")
        self.assertFalse(any(self.root.glob("ghidra-compatibility.*/distribution")))

    def test_valid_unix_distribution(self):
        self.fixture()
        result = self.download()
        self.assertEqual(result.returncode, 0, result.stderr)
        folders = list(self.root.glob("ghidra-compatibility.*/distribution/ghidra_12.0.0_PUBLIC"))
        self.assertEqual(len(folders), 1)
        self.assertTrue(os.access(folders[0] / "support/analyzeHeadless", os.X_OK))
        self.assertIn("GHIDRA_INSTALL_DIR=", self.output.read_text(encoding="utf-8"))

    def test_windows_extraction_branch(self):
        self.fixture()
        result = self.download(system="Windows")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("GHIDRA_INSTALL_DIR=", self.output.read_text(encoding="utf-8"))

    def test_checksum_mismatch(self):
        self.fixture()
        result = self.download(digest="sha256:" + "0" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertEqual(self.output.read_text(), "sentinel\n")
        self.assertFalse(any(self.root.glob("ghidra-compatibility.*/distribution")))

    def test_traversal_and_wrong_root(self):
        for extra in ("../outside", "../../outside", str(self.outside),
                      "ghidra_12.0.0_PUBLIC/../outside", "/absolute",
                      "other/support/file", "ghidra_12.0.0_PUBLIC/support\\outside"):
            with self.subTest(extra=extra):
                self.fixture(extra)
                self.rejected()

    def test_duplicate_member(self):
        self.fixture("ghidra_12.0.0_PUBLIC/support/launch.sh")
        self.rejected()

    def test_symlink_member(self):
        link = zipfile.ZipInfo("ghidra_12.0.0_PUBLIC/support/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.fixture(link)
        self.rejected()

    def test_member_count_limit(self):
        with zipfile.ZipFile(self.archive, "w") as archive:
            for index in range(40001):
                archive.writestr("ghidra_12.0.0_PUBLIC/item" + str(index), "")
        self.rejected()

    def test_expanded_size_limit(self):
        self.fixture()
        data = bytearray(self.archive.read_bytes())
        central = data.index(b"PK\x01\x02")
        struct.pack_into("<I", data, central + 24, 4 * 1024 * 1024 * 1024 - 1)
        self.archive.write_bytes(data)
        self.rejected()


@unittest.skipUnless(shutil.which("bash"), "bash is required")
class PackageStepTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        for name in ("build/compatibility", "dist", "tools", "tests"):
            (self.root / name).mkdir(parents=True)
        shutil.copyfile(ROOT / "tools/verify_extension.py", self.root / "tools/verify_extension.py")
        helpers = runpy.run_path(str(ROOT / "tests/test_packaging.py"))
        helpers["write_extension"](self.root / "dist/fixture.zip")
        self.script = run_script(ACTION.read_text(encoding="utf-8"), "Package and test extension")

    def tearDown(self):
        self.folder.cleanup()

    def execute(self, build_exit, headless_exit):
        build = self.root / "gradlew"
        build.write_text("#!/usr/bin/env bash\nprintf 'build fixture\\n'\nexit " + str(build_exit) + "\n")
        build.chmod(0o700)
        headless = self.root / "tests/test_real_ghidra.sh"
        headless.write_text("printf 'headless fixture\\n' >&2\nexit " + str(headless_exit) + "\n")
        return subprocess.run(["bash", "-c", self.script], cwd=self.root, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, timeout=10)

    def test_build_failure_stops_before_packaging(self):
        result = self.execute(23, 0)
        self.assertEqual(result.returncode, 23)
        self.assertIn("build fixture", (self.root / "build/compatibility/extension-build.log").read_text())
        self.assertFalse((self.root / "build/compatibility/tested-extension.zip").exists())
        self.assertFalse((self.root / "build/compatibility/headless.log").exists())

    def test_headless_failure_survives_tee(self):
        result = self.execute(0, 31)
        self.assertEqual(result.returncode, 31)
        self.assertTrue((self.root / "build/compatibility/tested-extension.zip").is_file())
        self.assertIn("headless fixture", (self.root / "build/compatibility/headless.log").read_text())


if __name__ == "__main__":
    unittest.main(verbosity=2)
