package turboheader.il2cpp.exporting;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class Il2CppOutputPathTest {
    private Il2CppOutputPathTest() {
    }

    public static void main(String[] args) throws IOException {
        preservesNormalPaths();
        encodesUnsafeCharacters();
        encodesUnicode();
        avoidsWindowsReservedNames();
        rejectsInvalidSegments();
        rejectsInvalidUnicode();
        keepsEncodedNamesDistinct();
        keepsUnicodeFormsDistinct();
        reservesEncoderMarkers();
        disambiguatesCaseCollisions();
        disambiguatesFileDirectoryCollisions();
        boundsLongComponents();
        remainsStableAcrossInputOrder();
        rejectsDuplicateIdentities();
        System.out.println("IL2CPP output path tests passed");
    }

    private static void preservesNormalPaths() throws IOException {
        var entry = entry("Fixture.Core", "World/Actor`1.cs");
        Path expected = Path.of("Fixture.Core", "World", "Actor`1.cpp");
        check(Il2CppOutputPath.forClass(entry).equals(expected), "normal output path");
        check(Il2CppOutputPath.forClasses(List.of(entry)).get(entry).equals(expected),
                "normal class-set output path");
    }

    private static void encodesUnsafeCharacters() {
        var entry = entry("Fixture:Core", "World/Actor?State.cs");
        check(Il2CppOutputPath.forClass(entry).equals(
                Path.of("Fixture~3ACore", "World", "Actor~3FState.cpp")),
                "unsafe filename characters");
    }

    private static void encodesUnicode() {
        var entry = entry("Fixture", "World/Caf\u00e9 State.cs");
        check(Il2CppOutputPath.forClass(entry).equals(
                Path.of("Fixture", "World", "Caf~C3~A9~20State.cpp")),
                "Unicode filename encoding");
    }

    private static void avoidsWindowsReservedNames() {
        var entry = entry("Fixture.", "Area./CON.cs");
        check(Il2CppOutputPath.forClass(entry).equals(
                Path.of("Fixture~2E", "Area~2E", "~RCON.cpp")), "portable output path");
    }

    private static void rejectsInvalidSegments() {
        expectFailure(() -> Il2CppOutputPath.forClass(entry("Fixture", "Area//Actor.cs")));
    }

    private static void rejectsInvalidUnicode() {
        var entry = new Il2CppClassCatalog.ClassEntry(
                "Fixture", "Bad\ud800.cs", Path.of("synthetic"));
        expectFailure(() -> Il2CppOutputPath.forClass(entry));
    }

    private static void keepsEncodedNamesDistinct() throws IOException {
        var first = entry("Fixture", "Actor?State.cs");
        var second = entry("Fixture", "Actor*State.cs");
        Map<Il2CppClassCatalog.ClassEntry, Path> outputs =
                Il2CppOutputPath.forClasses(List.of(first, second));
        check(outputs.get(first).endsWith("Actor~3FState.cpp"), "question mark encoding");
        check(outputs.get(second).endsWith("Actor~2AState.cpp"), "asterisk encoding");
    }

    private static void keepsUnicodeFormsDistinct() throws IOException {
        var composed = entry("Fixture", "Caf\u00e9.cs");
        var decomposed = entry("Fixture", "Cafe\u0301.cs");
        Map<Il2CppClassCatalog.ClassEntry, Path> outputs =
                Il2CppOutputPath.forClasses(List.of(composed, decomposed));
        check(!portableKey(outputs.get(composed)).equals(portableKey(outputs.get(decomposed))),
                "Unicode forms remain distinct");
    }

    private static void reservesEncoderMarkers() throws IOException {
        var reserved = entry("Fixture", "CON.cs");
        var literalMarker = entry("Fixture", "~RCON.cs");
        Map<Il2CppClassCatalog.ClassEntry, Path> outputs =
                Il2CppOutputPath.forClasses(List.of(reserved, literalMarker));
        check(outputs.get(reserved).endsWith("~RCON.cpp"), "reserved name marker");
        check(outputs.get(literalMarker).endsWith("~7ERCON.cpp"), "literal marker encoding");
    }

    private static void disambiguatesCaseCollisions() throws IOException {
        assertDisambiguated(entry("Fixture", "Actor.cs"),
                entry("Fixture", "actor.cs"), "Actor~C");
    }

    private static void disambiguatesFileDirectoryCollisions() throws IOException {
        var file = entry("Fixture", "Area.cs");
        var child = entry("Fixture", "Area.cpp/Actor.cs");
        Map<Il2CppClassCatalog.ClassEntry, Path> outputs =
                Il2CppOutputPath.forClasses(List.of(file, child));
        Map<Il2CppClassCatalog.ClassEntry, Path> reversed =
                Il2CppOutputPath.forClasses(List.of(child, file));
        check(outputs.get(file).getFileName().toString().startsWith("Area~C"),
                "file and directory collision suffix");
        check(outputs.get(child).equals(Path.of("Fixture", "Area.cpp", "Actor.cpp")),
                "nested output path");
        check(outputs.get(file).equals(reversed.get(file)) &&
                outputs.get(child).equals(reversed.get(child)),
                "file and directory collision ordering");
    }

    private static void boundsLongComponents() throws IOException {
        String prefix = "A".repeat(240);
        var first = entry("Fixture", prefix + "1.cs");
        var second = entry("Fixture", prefix + "2.cs");
        Path firstPath = Il2CppOutputPath.forClass(first);
        Path secondPath = Il2CppOutputPath.forClass(second);
        check(firstPath.getFileName().toString().length() <=
                PortableFilenameEncoder.MAX_COMPONENT_LENGTH, "bounded filename");
        check(!firstPath.equals(secondPath), "long filenames remain distinct");
        check(firstPath.getFileName().toString().contains("~H"), "truncation marker");
    }

    private static void remainsStableAcrossInputOrder() throws IOException {
        var first = entry("Fixture", "Actor.cs");
        var second = entry("Fixture", "actor.cs");
        Map<Il2CppClassCatalog.ClassEntry, Path> forward =
                Il2CppOutputPath.forClasses(List.of(first, second));
        Map<Il2CppClassCatalog.ClassEntry, Path> reverse =
                Il2CppOutputPath.forClasses(List.of(second, first));
        check(forward.get(first).equals(reverse.get(first)), "first stable output path");
        check(forward.get(second).equals(reverse.get(second)), "second stable output path");
    }

    private static void rejectsDuplicateIdentities() {
        var duplicate = entry("Fixture", "Actor.cs");
        try {
            Il2CppOutputPath.forClasses(List.of(duplicate, duplicate));
            throw new AssertionError("expected duplicate class identity failure");
        }
        catch (IOException expected) {
            check(expected.getMessage().contains("duplicate class identity"),
                    "duplicate identity message");
        }
    }

    private static Il2CppClassCatalog.ClassEntry entry(String assembly, String relative) {
        return new Il2CppClassCatalog.ClassEntry(
                assembly, relative, Path.of("synthetic", assembly, relative));
    }

    private static void expectFailure(Runnable action) {
        try {
            action.run();
            throw new AssertionError("expected invalid output path");
        }
        catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private static void assertDisambiguated(Il2CppClassCatalog.ClassEntry first,
            Il2CppClassCatalog.ClassEntry second, String readablePrefix) throws IOException {
        Map<Il2CppClassCatalog.ClassEntry, Path> outputs =
                Il2CppOutputPath.forClasses(List.of(first, second));
        Path firstPath = outputs.get(first);
        Path secondPath = outputs.get(second);
        check(firstPath.getFileName().toString().startsWith(readablePrefix),
                "first readable filename");
        check(secondPath.getFileName().toString().toLowerCase(Locale.ROOT)
                .startsWith(readablePrefix.toLowerCase(Locale.ROOT)),
                "second readable filename");
        check(!portableKey(firstPath).equals(portableKey(secondPath)),
                "portable output paths differ");
    }

    private static String portableKey(Path path) {
        return path.toString().replace('\\', '/').toLowerCase(Locale.ROOT);
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
