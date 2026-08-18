package turboheader.il2cpp;

public final class ImportDiagnosticsTest {
    public static void main(String[] args) {
        String warning = ImportDiagnostics.inferredExtentWarning(2_379);
        check(warning.contains("2,379 structure extents"), "formatted count");
        check(warning.contains("no runtime-authoritative total size"), "missing extent cause");
        check(warning.contains("Field offsets were not inferred"), "field-offset distinction");
        check(!warning.contains("use type_offsets.json schema 3"), "schema 3 is not prescribed");
        System.out.println("import diagnostic tests passed");
    }

    private static void check(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }
}
