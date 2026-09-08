package turboheader.il2cpp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class HeadlessRequestReaderTest {
    private HeadlessRequestReaderTest() {
    }

    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("turboheader-request-test-");
        try {
            Path header = write(directory, "il2cpp.h", "struct Il2CppObject {};\n");
            Path offsets = write(directory, "type_offsets.json", "{}\n");
            Path methods = write(directory, "script.json", "{}\n");
            readsValidImport(directory, header, offsets, methods);
            acceptsNullOptionalFiles(directory, header);
            rejectsUnknownField(directory, header);
            rejectsDuplicateField(directory, header);
            rejectsWrongPrimitiveType(directory, header);
            rejectsRelativePath(directory);
            rejectsRelativeManifestPath();
            rejectsTrailingData(directory, header);
            rejectsMalformedUtf8(directory);
            rejectsOversizedManifest(directory);
        }
        finally {
            try (var paths = Files.walk(directory)) {
                paths.sorted((left, right) -> right.compareTo(left)).forEach(path -> {
                    try {
                        Files.deleteIfExists(path);
                    }
                    catch (IOException error) {
                        throw new RuntimeException(error);
                    }
                });
            }
        }
    }

    private static void readsValidImport(Path directory, Path header, Path offsets,
            Path methods) throws Exception {
        Path request = write(directory, "valid.json", request(header, offsets, methods,
                "require-external-offsets"));
        var result = HeadlessRequestReader.readImport(request);
        check(result.header().equals(header.toRealPath()), "header path");
        check(result.offsets().equals(offsets.toRealPath()), "offset path");
        check(result.methods().equals(methods.toRealPath()), "method path");
        check(result.layoutPolicy() ==
                HeadlessRequestReader.LayoutPolicy.REQUIRE_EXTERNAL_OFFSETS, "layout policy");
    }

    private static void acceptsNullOptionalFiles(Path directory, Path header) throws Exception {
        Path request = write(directory, "optional.json", request(header, null, null,
                "allow-inferred"));
        var result = HeadlessRequestReader.readImport(request);
        check(result.offsets() == null, "null offsets");
        check(result.methods() == null, "null methods");
    }

    private static void rejectsUnknownField(Path directory, Path header) throws Exception {
        String json = request(header, null, null, "allow-inferred");
        expectFailure(write(directory, "unknown.json",
                json.replace("}", ",\"extra\":true}")), "unknown request field");
    }

    private static void rejectsDuplicateField(Path directory, Path header) throws Exception {
        String json = request(header, null, null, "allow-inferred");
        expectFailure(write(directory, "duplicate.json",
                json.replace("\"schema\":1", "\"schema\":1,\"schema\":1")),
                "duplicate request field");
    }

    private static void rejectsWrongPrimitiveType(Path directory, Path header) throws Exception {
        String json = request(header, null, null, "allow-inferred");
        expectFailure(write(directory, "wrong-type.json",
                json.replace("\"schema\":1", "\"schema\":\"1\"")),
                "schema must be an integer");
    }

    private static void rejectsRelativePath(Path directory) throws Exception {
        expectFailure(write(directory, "relative.json",
                request(Path.of("il2cpp.h"), null, null, "allow-inferred")),
                "header path must be absolute");
    }

    private static void rejectsTrailingData(Path directory, Path header) throws Exception {
        expectFailure(write(directory, "trailing.json",
                request(header, null, null, "allow-inferred") + "{}"),
                "trailing JSON data");
    }

    private static void rejectsRelativeManifestPath() throws Exception {
        expectFailure(Path.of("request.json"), "manifest path must be absolute");
    }

    private static void rejectsOversizedManifest(Path directory) throws Exception {
        Path request = directory.resolve("oversized.json");
        Files.writeString(request, " ".repeat(1024 * 1024 + 1), StandardCharsets.UTF_8);
        expectFailure(request, "exceeds 1 MiB");
    }

    private static void rejectsMalformedUtf8(Path directory) throws Exception {
        Path request = directory.resolve("malformed-utf8.json");
        Files.write(request, new byte[] { (byte) 0xc3, (byte) 0x28 });
        expectFailure(request, "not valid UTF-8");
    }

    private static String request(Path header, Path offsets, Path methods, String policy) {
        return "{\"schema\":1,\"operation\":\"import\",\"header\":" + quote(header) +
                ",\"offsets\":" + quote(offsets) + ",\"methods\":" + quote(methods) +
                ",\"layoutPolicy\":\"" + policy + "\"}";
    }

    private static String quote(Path path) {
        if (path == null) {
            return "null";
        }
        return "\"" + path.toString().replace("\\", "\\\\") + "\"";
    }

    private static Path write(Path directory, String name, String contents) throws IOException {
        return Files.writeString(directory.resolve(name), contents, StandardCharsets.UTF_8);
    }

    private static void expectFailure(Path path, String message) throws Exception {
        try {
            HeadlessRequestReader.readImport(path);
            throw new AssertionError("expected failure containing: " + message);
        }
        catch (IOException error) {
            check(error.getMessage().contains(message), "error message: " + error.getMessage());
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
