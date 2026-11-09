import base64
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
JDK = Path(os.environ["JAVA_HOME"]) if os.environ.get("JAVA_HOME") else Path(shutil.which("javac")).resolve().parents[1]
JAVA = JDK / "bin" / ("java.exe" if os.name == "nt" else "java")
JAVAC = JDK / "bin" / ("javac.exe" if os.name == "nt" else "javac")
CHECKSUM = "a" * 64


class LauncherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiled = tempfile.TemporaryDirectory(prefix="gradle fixture ")
        classes = Path(cls.compiled.name)
        subprocess.run([str(JAVAC), "-d", str(classes), str(ROOT / "tools/GhidraGradle.java"),
                        str(ROOT / "tests/launcher/GradleFixture.java"),
                        str(ROOT / "tests/launcher/GhidraGradleTest.java")], check=True)
        cls.classes = classes

    @classmethod
    def tearDownClass(cls):
        cls.compiled.cleanup()

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="gradle launcher ")
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.project = self.root / "project with spaces"
        self.sdk = self.root / "SDK with spaces"
        self.temp = self.root / "temporary"
        self.temp.mkdir()
        (self.project / "tools").mkdir(parents=True)
        (self.project / "gradle/wrapper").mkdir(parents=True)
        (self.sdk / "Ghidra").mkdir(parents=True)
        (self.sdk / "support/gradle").mkdir(parents=True)
        for file in ("gradlew", "gradlew.bat", "tools/GhidraGradle.java"):
            shutil.copy2(ROOT / file, self.project / file)
        self.application = self.sdk / "Ghidra/application.properties"
        self.application.write_text("application.java.compiler=21\napplication.java.min=21\n")
        (self.sdk / "support/buildExtension.gradle").write_text("// fixture\n")
        self.wrapper = self.sdk / "support/gradle/gradle-wrapper.properties"
        self.wrapper.write_text("distributionUrl=https://services.gradle.org/distributions/gradle-9.8.0-bin.zip\n")
        (self.project / "gradle/checksums.properties").write_text("9.8.0=" + CHECKSUM + "\n")
        with zipfile.ZipFile(self.project / "gradle/wrapper/gradle-wrapper.jar", "w") as jar:
            jar.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nMain-Class: GradleFixture\n\n")
            jar.write(self.classes / "GradleFixture.class", "GradleFixture.class")
        self.env = dict(os.environ, JAVA_HOME=str(JDK), GHIDRA_INSTALL_DIR=str(self.sdk),
                        JAVA_OPTS='"-Djava.io.tmpdir=' + str(self.temp) + '"', GRADLE_OPTS="")
        self.outside = self.root / "outside"
        self.outside.write_text("unchanged")

    def launch(self, *args, environment=None):
        if os.name == "nt":
            command = ["cmd.exe", "/d", "/c", "gradlew.bat"]
        else:
            command = ["sh", str(self.project / "gradlew")]
        result = subprocess.run(command + list(args), cwd=self.project,
                                env=environment or self.env, text=True, capture_output=True, timeout=30)
        self.assertEqual(self.outside.read_text(), "unchanged")
        self.assertEqual(list(self.temp.glob("turboheader-gradle-*")), [])
        self.assertEqual(self.wrapper.read_text(),
                         "distributionUrl=https://services.gradle.org/distributions/gradle-9.8.0-bin.zip\n")
        return result

    def assert_directory(self, output, expected):
        directories = [line[len("directory="):] for line in output.splitlines()
                       if line.startswith("directory=")]
        self.assertEqual(len(directories), 1, output)
        actual = Path(directories[0])
        self.assertTrue(actual.samefile(expected), f"{actual} is not the expected directory {expected}")

    def test_policy_units(self):
        subprocess.run([str(JAVA), "-cp", str(self.classes), "GhidraGradleTest"], check=True)

    def test_arguments_and_paths_preserved(self):
        arguments = ["buildExtension", "-Pnote=a b", "-Pnote=$(touch injected)"]
        result = self.launch(*arguments)
        self.assertEqual(result.returncode, 0, result.stderr)
        for arg in arguments:
            self.assertIn("argument=" + base64.b64encode(arg.encode()).decode(), result.stdout)
        self.assertIn("checksum=" + CHECKSUM, result.stdout)
        self.assert_directory(result.stdout, self.project)
        self.assertFalse((self.project / "injected").exists())

    def test_native_project_directory(self):
        result = self.launch("--ghidra-native", ":Decompiler:buildNatives")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_directory(result.stdout, self.sdk / "support/gradle")

    def test_project_directory_alias(self):
        alias = self.root / "project alias"
        try:
            alias.symlink_to(self.project, target_is_directory=True)
        except OSError as error:
            if os.name == "nt" and getattr(error, "winerror", None) == 1314:
                self.skipTest("Creating symlinks requires Windows Developer Mode or privileges")
            raise
        self.project = alias
        result = self.launch("buildExtension")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_directory(result.stdout, alias)

    def test_different_directory_rejected(self):
        with self.assertRaises(AssertionError):
            self.assert_directory("directory=" + str(self.project), self.sdk)

    def test_missing_or_duplicate_directory_rejected(self):
        for output in ("", "directory=" + str(self.project) + "\ndirectory=" + str(self.sdk)):
            with self.subTest(output=output), self.assertRaises(AssertionError):
                self.assert_directory(output, self.project)

    def test_child_exit_code(self):
        result = self.launch("--fixture-fail")
        self.assertEqual(result.returncode, 23, result.stderr)

    def test_missing_sdk(self):
        environment = self.env.copy()
        environment.pop("GHIDRA_INSTALL_DIR")
        result = self.launch(environment=environment)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Set GHIDRA_INSTALL_DIR", result.stderr)
        self.assertNotIn("checksum=", result.stdout)

    def test_property_forms(self):
        environment = self.env.copy()
        environment.pop("GHIDRA_INSTALL_DIR")
        for args in (["-PGHIDRA_INSTALL_DIR=" + str(self.sdk)],
                     ["-P", "GHIDRA_INSTALL_DIR=" + str(self.sdk)],
                     ["--project-prop=GHIDRA_INSTALL_DIR=" + str(self.sdk)],
                     ["--project-prop", "GHIDRA_INSTALL_DIR=" + str(self.sdk)]):
            with self.subTest(args=args):
                result = self.launch(*args, environment=environment)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_metadata_query_before_java_upgrade(self):
        self.application.write_text("application.java.compiler=25\napplication.java.min=25\n")
        result = self.launch("--ghidra-java-version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "25")

    def test_newer_jdk_rejected_before_wrapper(self):
        self.application.write_text("application.java.compiler=99\napplication.java.min=99\n")
        result = self.launch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires JDK 99", result.stderr)
        self.assertNotIn("checksum=", result.stdout)

    def test_runtime_only_java_home(self):
        runtime = self.root / "runtime"
        (runtime / "bin").mkdir(parents=True)
        java_name = "java.exe" if os.name == "nt" else "java"
        shutil.copy2(JAVA, runtime / "bin" / java_name)
        result = self.launch(environment=dict(self.env, JAVA_HOME=str(runtime)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("full JDK", result.stderr)

    def test_invalid_sdk_url_cannot_start_wrapper(self):
        self.wrapper.write_text("distributionUrl=file:///outside/gradle.zip\n")
        result = subprocess.run([str(JAVA), str(self.project / "tools/GhidraGradle.java"),
                                 str(self.project)], cwd=self.project, env=self.env,
                                text=True, capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("official Gradle", result.stderr)
        self.assertNotIn("checksum=", result.stdout)
        self.assertEqual(self.outside.read_text(), "unchanged")
        self.assertEqual(list(self.temp.glob("turboheader-gradle-*")), [])

    def test_wrong_checksum_rejected_before_wrapper(self):
        (self.project / "gradle/checksums.properties").write_text("9.8.0=invalid\n")
        result = self.launch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid Gradle SHA-256", result.stderr)
        self.assertNotIn("checksum=", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
