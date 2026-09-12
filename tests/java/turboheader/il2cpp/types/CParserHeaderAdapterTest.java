package turboheader.il2cpp.types;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class CParserHeaderAdapterTest {
    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("turboheader-cparser-test");
        try {
            convertsInheritanceAndDeletesTemporaryHeader(directory);
            rejectsPreprocessorForms(directory);
            rejectsInvalidUtf8(directory);
            rejectsControlCharacters(directory);
            enforcesTheStreamingSizeLimit(directory);
        }
        finally {
            try (var paths = Files.list(directory)) {
                check(paths.findAny().isEmpty(), "temporary files were not removed");
            }
            Files.delete(directory);
        }
        System.out.println("CParser header adapter tests passed");
    }

    private static void convertsInheritanceAndDeletesTemporaryHeader(Path directory)
            throws Exception {
        Path source = directory.resolve("valid.h");
        Files.writeString(source, "struct Base {\n};\nstruct Child : Base {\n int value;\n};\n");
        Path converted;
        try (var header = CParserHeaderAdapter.prepare(source, 8, directory)) {
            converted = header.path();
            String contents = Files.readString(converted);
            check(header.inheritanceConversions() == 1, "inheritance conversion count");
            check(contents.contains("struct Child {\n Base super;\n"),
                    "inheritance was not converted");
            check(contents.contains("typedef __int64 intptr_t;"), "64-bit preamble");
        }
        check(!Files.exists(converted), "prepared header was not deleted");
        Files.delete(source);
    }

    private static void rejectsPreprocessorForms(Path directory) throws Exception {
        for (String token : new String[] { "#include", "%:include", "??=include" }) {
            Path source = directory.resolve("directive.h");
            Files.writeString(source, token + " \"outside.h\"\n");
            expectFailure(() -> CParserHeaderAdapter.prepare(source, 8, directory),
                    "preprocessor token");
            Files.delete(source);
        }
    }

    private static void rejectsInvalidUtf8(Path directory) throws Exception {
        Path source = directory.resolve("invalid-utf8.h");
        Files.write(source, new byte[] { (byte) 0xc3, (byte) 0x28 });
        expectFailure(() -> CParserHeaderAdapter.prepare(source, 8, directory),
                "invalid UTF-8");
        Files.delete(source);
    }

    private static void rejectsControlCharacters(Path directory) throws Exception {
        Path source = directory.resolve("control.h");
        Files.writeString(source, "struct Value {\u0000 int field; };\n");
        expectFailure(() -> CParserHeaderAdapter.prepare(source, 8, directory),
                "control character");
        Files.delete(source);
    }

    private static void enforcesTheStreamingSizeLimit(Path directory) throws Exception {
        Path source = directory.resolve("large.h");
        Files.writeString(source, "struct LargerThanLimit {};\n");
        expectFailure(() -> CParserHeaderAdapter.prepare(source, 8, directory, 8),
                "size limit");
        Files.delete(source);
    }

    private static void expectFailure(ThrowingOperation operation, String label) throws Exception {
        try {
            operation.run();
            throw new AssertionError(label);
        }
        catch (IOException expected) {
            // Expected failure.
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private interface ThrowingOperation {
        void run() throws Exception;
    }
}
