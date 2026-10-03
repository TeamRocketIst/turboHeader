#!/usr/bin/env python3
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import tempfile
import unittest

from test_compatibility_workflow import release as ghidra_release, run_script

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/weekly-ghidra-release.yml"


def release():
    return {
        "id": 42,
        "tag_name": "v1.0.0",
        "draft": False,
        "prerelease": False,
        "published_at": "2026-01-01T00:00:00Z",
        "assets": [],
    }


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_release_safety_invariants(self):
        runpy.run_path(str(ROOT / "tests/test_release_workflow.py"))["check_workflow"]()

    def test_every_job_uses_the_same_commit(self):
        jobs = re.split(r"^  ([a-z-]+):\n", self.workflow.split("\njobs:\n", 1)[1], flags=re.MULTILINE)
        self.assertEqual(jobs[1], "discover")
        for name, body in zip(jobs[3::2], jobs[4::2]):
            with self.subTest(job=name):
                self.assertIn("- uses: actions/checkout@v6\n        with:\n"
                              "          ref: ${{ needs.discover.outputs.source_sha }}", body)
        self.assertEqual(len(jobs[3::2]), 6)
        self.assertIn("source_sha: ${{ steps.source.outputs.source_sha }}", self.workflow)
        self.assertIn("release_id: ${{ steps.source.outputs.release_id }}", self.workflow)

    def test_no_release_creation_or_branch_fallback(self):
        self.assertNotIn("gh release create", self.workflow)
        self.assertNotIn("$GITHUB_SHA", self.workflow)
        self.assertNotIn("--latest", self.workflow)
        source = run_script(self.workflow, "Select released TurboHeader source")
        self.assertNotIn("|| true", source)
        self.assertNotIn("target_commitish", source)
        self.assertIn("git fetch --no-tags origin", source)
        self.assertIn("FETCH_HEAD^{commit}", source)
        self.assertIn('git checkout --detach "$source_sha"', source)
        self.assertLess(source.index("git checkout"), source.index("extension_version="))
        self.assertLess(self.workflow.index("Check release-source selection"),
                        self.workflow.index("Select released TurboHeader source"))

    def test_inputs_do_not_enter_shell_source(self):
        for name in ("Select released TurboHeader source", "Find the Ghidra release",
                     "Preserve existing compatibility archives", "Publish compatibility release"):
            with self.subTest(step=name):
                self.assertNotIn("${{", run_script(self.workflow, name))

    def test_release_identity_is_rechecked_before_upload(self):
        publish = run_script(self.workflow, "Publish compatibility release")
        upload = publish.index("gh release upload")
        self.assertLess(publish.index(".id == $id"), upload)
        self.assertLess(publish.index("git fetch"), upload)
        self.assertLess(publish.index('== "$SOURCE_SHA"'), upload)
        self.assertIn('gh release edit "$RELEASE_TAG"', publish)


@unittest.skipUnless(all(shutil.which(tool) for tool in ("bash", "git", "jq")), "bash, git and jq are required")
class ReleaseSourceTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        self.origin = self.root / "origin"
        self.checkout = self.root / "checkout"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.output = self.root / "outputs"
        self.output.write_text("sentinel\n", encoding="utf-8")
        self.commands = self.root / "commands.jsonl"
        self.outside = self.root / "outside"
        self.outside.write_text("unchanged", encoding="utf-8")
        self.env = os.environ.copy()
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_TERMINAL_PROMPT="0", GIT_AUTHOR_NAME="Sample", GIT_AUTHOR_EMAIL="sample@example.invalid",
                        GIT_COMMITTER_NAME="Sample", GIT_COMMITTER_EMAIL="sample@example.invalid")
        self.git(self.root, "init", "-b", "release", str(self.origin))
        self.properties = self.origin / "extension.properties"
        self.properties.write_text("name=sample\nversion=1.0.0\n", encoding="utf-8")
        self.notes = self.origin / ".github/release-notes/v1.0.0.md"
        self.notes.parent.mkdir(parents=True)
        self.notes.write_text("Sample release notes.\n", encoding="utf-8")
        self.git(self.origin, "add", ".")
        self.git(self.origin, "commit", "-m", "sample release")
        self.source_sha = self.git(self.origin, "rev-parse", "HEAD").strip()
        self.git(self.origin, "tag", "v1.0.0")
        self.git(self.origin, "checkout", "-b", "main")
        self.properties.write_text("name=sample\nversion=9.0.0\n", encoding="utf-8")
        self.git(self.origin, "commit", "-am", "sample development")
        self.main_sha = self.git(self.origin, "rev-parse", "HEAD").strip()
        self.git(self.root, "clone", "--no-local", "--branch", "main", str(self.origin), str(self.checkout))
        gh = self.bin / "gh"
        gh.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "with pathlib.Path(os.environ['MOCK_COMMANDS']).open('a') as log:\n"
            "    log.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            "if sys.argv[1] == 'api':\n"
            "    if int(os.environ.get('MOCK_API_EXIT', '0')):\n"
            "        sys.exit(int(os.environ['MOCK_API_EXIT']))\n"
            "    data = 'MOCK_GHIDRA' if 'NationalSecurityAgency/ghidra' in sys.argv[2] else 'MOCK_RELEASE'\n"
            "    print(os.environ[data])\n"
            "elif sys.argv[1:3] == ['release', 'download']:\n"
            "    name = sys.argv[sys.argv.index('--pattern') + 1]\n"
            "    folder = pathlib.Path(sys.argv[sys.argv.index('--dir') + 1])\n"
            "    (folder / name).write_bytes(b'sample archive')\n"
            "elif sys.argv[1:3] not in (['release', 'upload'], ['release', 'edit']):\n"
            "    sys.exit(99)\n", encoding="utf-8")
        gh.chmod(0o700)
        self.env.update(PATH=str(self.bin) + os.pathsep + self.env["PATH"],
                        GITHUB_REPOSITORY="Sample/project", GITHUB_OUTPUT=str(self.output),
                        MOCK_COMMANDS=str(self.commands), MOCK_RELEASE=json.dumps(release()),
                        MOCK_GHIDRA=json.dumps(ghidra_release()), REQUESTED_TAG="",
                        RELEASE_TAG="v1.0.0", RELEASE_ID="42", EXTENSION_VERSION="1.0.0",
                        SOURCE_SHA=self.source_sha, TMPDIR=str(self.root))
        self.workflow = WORKFLOW.read_text(encoding="utf-8")

    def tearDown(self):
        self.folder.cleanup()

    def git(self, cwd, *args):
        result = subprocess.run(["git", *args], cwd=cwd, env=self.env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def run_step(self, name, data=None, api_exit=0):
        env = self.env.copy()
        if data is not None:
            env["MOCK_RELEASE"] = json.dumps(data)
        env["MOCK_API_EXIT"] = str(api_exit)
        return subprocess.run(["bash", "-c", run_script(self.workflow, name)], cwd=self.checkout,
                              env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)

    def logged_commands(self):
        if not self.commands.exists():
            return []
        return [json.loads(line) for line in self.commands.read_text().splitlines()]

    def assert_rejected(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output.read_text(), "sentinel\n")
        self.assertEqual(self.outside.read_text(), "unchanged")
        self.assertFalse((self.checkout / "injected").exists())
        self.assertFalse(any(command[:2] in (["release", "upload"], ["release", "edit"])
                             for command in self.logged_commands()))

    def select(self, data=None, api_exit=0):
        return self.run_step("Select released TurboHeader source", data, api_exit)

    def prepare_publish(self):
        result = self.select()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.output.write_text("sentinel\n", encoding="utf-8")
        assets = self.checkout / "release-assets"
        assets.mkdir()
        (assets / "turboheader-1.0.0-ghidra-12.0.0-linux_x86_64.zip").write_bytes(b"sample archive")
        (assets / "SHA256SUMS").write_text("sample checksum\n", encoding="utf-8")

    def test_lightweight_tag_not_main(self):
        result = self.select()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.git(self.checkout, "rev-parse", "HEAD").strip(), self.source_sha)
        self.assertNotEqual(self.source_sha, self.main_sha)
        self.assertIn("source_sha=" + self.source_sha + "\n", self.output.read_text())
        self.assertIn("extension_version=1.0.0\n", self.output.read_text())
        self.assertIn("release_id=42\n", self.output.read_text())
        self.assertEqual(self.logged_commands(), [["api", "repos/Sample/project/releases/latest"]])
        self.assertNotEqual(subprocess.run(["git", "symbolic-ref", "-q", "HEAD"], cwd=self.checkout,
                                          env=self.env, capture_output=True).returncode, 0)

    def test_annotated_tag_peels_to_commit(self):
        self.git(self.origin, "tag", "-fa", "v1.0.0", self.source_sha, "-m", "sample tag")
        result = self.select()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("source_sha=" + self.source_sha + "\n", self.output.read_text())

    def test_api_failure_has_no_main_fallback(self):
        self.assert_rejected(self.select(api_exit=1))
        self.assertEqual(self.git(self.checkout, "rev-parse", "HEAD").strip(), self.main_sha)

    def test_bad_release_metadata(self):
        for field, values in (("draft", [True, None, "false"]), ("prerelease", [True, None]),
                              ("published_at", [None, "", 42]), ("id", [0, -1, 1.5, "42", None])):
            for value in values:
                with self.subTest(field=field, value=value):
                    data = release()
                    data[field] = value
                    self.assert_rejected(self.select(data))
                    self.assertEqual(self.git(self.checkout, "rev-parse", "HEAD").strip(), self.main_sha)
        for data in ({}, [], "invalid", {"message": "Not Found"}):
            with self.subTest(data=data):
                self.assert_rejected(self.select(data))

    def test_tags_are_allowlisted_before_fetch(self):
        for tag in ("main", "../main", "--help", "v1.0.0; touch injected", "$(touch injected)",
                    "v1.0.0\nsource_sha=main", "v1.0.0\n", "v1.0.0-ghidra-12.0.0", "v1.0.0-rc1", None):
            with self.subTest(tag=tag):
                data = release()
                data["tag_name"] = tag
                self.assert_rejected(self.select(data))
                self.assertEqual(self.git(self.checkout, "rev-parse", "HEAD").strip(), self.main_sha)

    def test_missing_tag_has_no_stale_fetch_head_fallback(self):
        self.git(self.checkout, "fetch", "origin", "main")
        data = release()
        data["tag_name"] = "v2.0.0"
        self.assert_rejected(self.select(data))
        self.assertEqual(self.git(self.checkout, "rev-parse", "HEAD").strip(), self.main_sha)

    def test_noncommit_tag_is_rejected(self):
        blob = self.git(self.origin, "rev-parse", self.source_sha + ":extension.properties").strip()
        self.git(self.origin, "tag", "-f", "v1.0.0", blob)
        self.assert_rejected(self.select())
        self.assertEqual(self.git(self.checkout, "rev-parse", "HEAD").strip(), self.main_sha)

    def test_version_mismatch_is_rejected(self):
        self.git(self.origin, "tag", "-f", "v1.0.0", self.main_sha)
        self.assert_rejected(self.select())

    def test_duplicate_version_is_rejected(self):
        with (self.origin / "extension.properties").open("a") as file:
            file.write("version=1.0.0\n")
        self.git(self.origin, "commit", "-am", "sample duplicate")
        self.git(self.origin, "tag", "-f", "v1.0.0")
        self.assert_rejected(self.select())

    def test_missing_notes_are_rejected(self):
        self.git(self.origin, "rm", str(self.notes.relative_to(self.origin)))
        self.properties.write_text("version=1.0.0\n", encoding="utf-8")
        self.git(self.origin, "commit", "-am", "sample missing notes")
        self.git(self.origin, "tag", "-f", "v1.0.0")
        self.assert_rejected(self.select())

    def test_complete_compatibility_assets_skip_build(self):
        data = release()
        platforms = ["win_x86_64", "mac_x86_64", "mac_aarch64", "linux_x86_64", "linux_aarch64"]
        data["assets"] = [{"name": "turboheader-1.0.0-ghidra-12.0.0-" + platform + ".zip"}
                          for platform in platforms] + [{"name": "SHA256SUMS"}]
        result = self.run_step("Find the Ghidra release", data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("build=false\n", self.output.read_text())
        self.assertIn("extension_version=1.0.0\n", self.output.read_text())

    def test_missing_asset_or_checksum_requires_build(self):
        platforms = ["win_x86_64", "mac_x86_64", "mac_aarch64", "linux_x86_64", "linux_aarch64"]
        complete = [{"name": "turboheader-1.0.0-ghidra-12.0.0-" + platform + ".zip"}
                    for platform in platforms] + [{"name": "SHA256SUMS"}]
        for index in range(len(complete)):
            with self.subTest(missing=complete[index]):
                data = release()
                data["assets"] = complete[:index] + complete[index + 1:]
                result = self.run_step("Find the Ghidra release", data)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("build=true\n", self.output.read_text())

    def test_discovery_rejects_changed_release_identity(self):
        for field, value in (("id", 43), ("tag_name", "v2.0.0"), ("draft", True),
                             ("prerelease", True), ("assets", None)):
            with self.subTest(field=field):
                data = release()
                data[field] = value
                self.assert_rejected(self.run_step("Find the Ghidra release", data))

    def test_publish_updates_existing_release_only(self):
        self.prepare_publish()
        result = self.run_step("Publish compatibility release")
        self.assertEqual(result.returncode, 0, result.stderr)
        writes = [command for command in self.logged_commands() if command[0] == "release"]
        self.assertEqual([command[:3] for command in writes], [["release", "upload", "v1.0.0"],
                                                               ["release", "edit", "v1.0.0"]])
        notes_path = Path(writes[1][writes[1].index("--notes-file") + 1])
        self.assertIn("Sample release notes.", notes_path.read_text())
        self.assertIn("12.0.0", notes_path.read_text())
        self.assertNotIn("--latest", writes[1])

    def test_publish_rejects_moved_tag(self):
        self.prepare_publish()
        self.git(self.origin, "tag", "-f", "v1.0.0", self.main_sha)
        self.assert_rejected(self.run_step("Publish compatibility release"))

    def test_publish_rejects_changed_release(self):
        self.prepare_publish()
        for field, value in (("id", 43), ("tag_name", "v2.0.0"), ("draft", True), ("prerelease", True)):
            with self.subTest(field=field):
                data = release()
                data[field] = value
                self.assert_rejected(self.run_step("Publish compatibility release", data))

    def test_publish_api_failure_does_not_create_release(self):
        self.prepare_publish()
        self.assert_rejected(self.run_step("Publish compatibility release", api_exit=1))

    def test_preservation_rejects_moved_tag_before_download(self):
        self.prepare_publish()
        self.git(self.origin, "tag", "-f", "v1.0.0", self.main_sha)
        self.assert_rejected(self.run_step("Preserve existing compatibility archives"))
        self.assertFalse((self.checkout / "existing-assets").exists())

    def test_existing_archives_are_preserved(self):
        self.prepare_publish()
        data = release()
        old_asset = "turboheader-1.0.0-ghidra-11.0.0-linux_x86_64.zip"
        data["assets"] = [{"name": old_asset}]
        result = self.run_step("Preserve existing compatibility archives", data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.checkout / "release-assets" / old_asset).read_bytes(), b"sample archive")


if __name__ == "__main__":
    unittest.main()
