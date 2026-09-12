package turboheader.il2cpp.exporting;

import java.io.IOException;
import java.nio.file.Path;
import java.text.Normalizer;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class Il2CppOutputPathTest {
    private Il2CppOutputPathTest() {
    }

    public static void main(String[] args) throws IOException {
        preservesNormalPaths();
        replacesUnsafeCharacters();
        avoidsWindowsReservedNames();
        rejectsInvalidSegments();
        disambiguatesSanitizedCollisions();
        disambiguatesCaseCollisions();
        disambiguatesUnicodeEquivalentCollisions();
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

    private static void replacesUnsafeCharacters() {
        var entry = entry("Fixture:Core", "World/Actor?State.cs");
        check(Il2CppOutputPath.forClass(entry).equals(
                Path.of("Fixture_Core", "World", "Actor_State.cpp")),
                "unsafe filename characters");
    }

    private static void avoidsWindowsReservedNames() {
        var entry = entry("Fixture.", "Area./CON.cs");
        check(Il2CppOutputPath.forClass(entry).equals(
                Path.of("Fixture_", "Area_", "_CON.cpp")), "portable output path");
    }

    private static void rejectsInvalidSegments() {
        expectFailure(() -> Il2CppOutputPath.forClass(entry("Fixture", "Area//Actor.cs")));
    }

    private static void disambiguatesSanitizedCollisions() throws IOException {
        assertDisambiguated(entry("Fixture", "Actor?State.cs"),
                entry("Fixture", "Actor*State.cs"), "Actor_State__");
    }

    private static void disambiguatesCaseCollisions() throws IOException {
        assertDisambiguated(entry("Fixture", "Actor.cs"),
                entry("Fixture", "actor.cs"), "Actor__");
    }

    private static void disambiguatesUnicodeEquivalentCollisions() throws IOException {
        assertDisambiguated(entry("Fixture", "Caf\u00e9.cs"),
                entry("Fixture", "Cafe\u0301.cs"), "Caf");
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
        String portable = path.toString().replace('\\', '/');
        return Normalizer.normalize(portable, Normalizer.Form.NFC)
                .toLowerCase(Locale.ROOT);
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
