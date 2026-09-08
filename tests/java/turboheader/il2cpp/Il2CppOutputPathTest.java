package turboheader.il2cpp;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

public final class Il2CppOutputPathTest {
    private Il2CppOutputPathTest() {
    }

    public static void main(String[] args) {
        preservesNormalPaths();
        replacesUnsafeCharacters();
        avoidsWindowsReservedNames();
        rejectsInvalidSegments();
        rejectsSanitizedCollisions();
        rejectsCaseCollisions();
        rejectsUnicodeEquivalentCollisions();
        System.out.println("IL2CPP output path tests passed");
    }

    private static void preservesNormalPaths() {
        var entry = entry("Fixture.Core", "World/Actor`1.cs");
        check(Il2CppOutputPath.forClass(entry).equals(
                Path.of("Fixture.Core", "World", "Actor`1.cpp")), "normal output path");
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

    private static void rejectsSanitizedCollisions() {
        expectCollision(entry("Fixture", "Actor?State.cs"),
                entry("Fixture", "Actor*State.cs"));
    }

    private static void rejectsCaseCollisions() {
        expectCollision(entry("Fixture", "Actor.cs"), entry("fixture", "actor.cs"));
    }

    private static void rejectsUnicodeEquivalentCollisions() {
        expectCollision(entry("Fixture", "Caf\u00e9.cs"),
                entry("Fixture", "Cafe\u0301.cs"));
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

    private static void expectCollision(Il2CppClassCatalog.ClassEntry first,
            Il2CppClassCatalog.ClassEntry second) {
        try {
            Il2CppOutputPath.forClasses(List.of(first, second));
            throw new AssertionError("expected output path collision");
        }
        catch (IOException expected) {
            check(expected.getMessage().contains("collision"), "collision message");
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
