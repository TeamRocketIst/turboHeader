package turboheader.il2cpp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public final class Il2CppClassCatalogTest {
    private Il2CppClassCatalogTest() {
    }

    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("turboheader-catalog-test-");
        try {
            discoversClassesInStableOrder(directory);
            preservesClassIdentity(directory);
            appliesAssemblyAndClassSelection(directory);
            appliesBoundaryAwareFrameworkRules(directory);
            appliesDefaultWhitelistAndAllScope(directory);
            rejectsSymlinks(directory);
            rejectsSymlinkedRuleFile(directory);
            rejectsMalformedRuleFile(directory);
            rejectsLongRule(directory);
            rejectsOversizedRuleFiles(directory);
            System.out.println("IL2CPP class catalog tests passed");
        }
        finally {
            deleteTree(directory);
        }
    }

    private static void discoversClassesInStableOrder(Path directory) throws Exception {
        Path root = Files.createDirectory(directory.resolve("ordered"));
        write(root, "Zeta/Space/Second.cs");
        write(root, "Alpha/Root.cs");
        write(root, "Alpha/Area/First.CS");
        write(root, "Alpha/readme.txt");

        var classes = Il2CppClassCatalog.scan(root);
        check(classes.stream().map(Il2CppClassCatalog.ClassEntry::displayName).toList().equals(
                List.of("Alpha/Area/First", "Alpha/Root", "Zeta/Space/Second")),
                "stable discovery order");
    }

    private static void preservesClassIdentity(Path directory) throws Exception {
        Path root = Files.createDirectory(directory.resolve("identity"));
        write(root, "Game.Core/World/Actors/Runner.cs");

        var entry = Il2CppClassCatalog.scan(root).get(0);
        check(entry.assembly().equals("Game.Core"), "assembly name");
        check(entry.relativeSource().equals("World/Actors/Runner.cs"), "relative source");
        check(entry.namespaceName().equals("World.Actors"), "namespace name");
        check(entry.className().equals("Runner"), "class name");
        check(entry.selectionKeys().contains("world.actors.runner"), "selection key");
        check(entry.candidateNames().contains("World_Actors_Runner"), "candidate name");
    }

    private static void appliesAssemblyAndClassSelection(Path directory) throws Exception {
        Path root = Files.createDirectory(directory.resolve("selection"));
        write(root, "Game.One/Area/Actor.cs");
        write(root, "Game.One/Area/Camera.cs");
        write(root, "Game.Two/Area/Actor.cs");
        var classes = Il2CppClassCatalog.scan(root);

        var selected = Il2CppClassSelector.select(classes, Il2CppExportScope.WHITELIST,
                List.of("gAmE.oNe.DLL"), List.of("Area.Actor.cpp"), null);
        check(selected.classes().size() == 1, "selected class count");
        check(selected.classes().get(0).displayName().equals("Game.One/Area/Actor"),
                "selected class identity");
        check(!selected.assemblies().get("game.two").included(), "excluded assembly");
    }

    private static void appliesBoundaryAwareFrameworkRules(Path directory) throws Exception {
        Path root = Files.createDirectory(directory.resolve("frameworks"));
        write(root, "Toolkit/Root.cs");
        write(root, "Toolkit.Core/Core.cs");
        write(root, "Toolkit-Plugin/Plugin.cs");
        write(root, "ToolkitExtra/App.cs");
        Path rules = directory.resolve("framework-rules.txt");
        Files.writeString(rules, "# synthetic rule\nToolkit # comment\n", StandardCharsets.UTF_8);

        var selected = Il2CppClassSelector.select(Il2CppClassCatalog.scan(root),
                Il2CppExportScope.BLACKLIST, List.of(), List.of(), rules);
        check(selected.classes().size() == 1, "framework selection count");
        check(selected.classes().get(0).assembly().equals("ToolkitExtra"),
                "framework boundary");
        check(Il2CppClassSelector.matchesFramework("System.Core", "System"),
                "dot boundary");
        check(!Il2CppClassSelector.matchesFramework("Systematic", "System"),
                "prefix boundary");
        check(Il2CppClassSelector.matchesFramework("TOOLKIT.Core.DLL", "toolkit"),
                "case-insensitive DLL boundary");
    }

    private static void appliesDefaultWhitelistAndAllScope(Path directory) throws Exception {
        Path root = Files.createDirectory(directory.resolve("scopes"));
        write(root, "Assembly-CSharp/Main.cs");
        write(root, "Assembly-CSharp-firstpass/Legacy.cs");
        write(root, "Vendor/Library.cs");
        var classes = Il2CppClassCatalog.scan(root);

        var whitelist = Il2CppClassSelector.select(classes, Il2CppExportScope.WHITELIST,
                List.of(), List.of(), null);
        check(whitelist.classes().size() == 2, "default whitelist count");

        var all = Il2CppClassSelector.select(classes, Il2CppExportScope.ALL,
                List.of(), List.of(), null);
        check(all.classes().size() == 3, "all scope count");
    }

    private static void rejectsSymlinks(Path directory) throws Exception {
        Path root = Files.createDirectory(directory.resolve("links"));
        Path target = write(root, "Game/Target.cs");
        try {
            Files.createSymbolicLink(root.resolve("Game/Linked.cs"), target);
        }
        catch (UnsupportedOperationException | IOException error) {
            return;
        }

        expectFailure(() -> Il2CppClassCatalog.scan(root), "symbolic links");

        Path assemblyRoot = Files.createDirectory(directory.resolve("assembly-links"));
        Path assemblyTarget = Files.createDirectory(directory.resolve("assembly-target"));
        write(assemblyTarget, "Nested/Class.cs");
        try {
            Files.createSymbolicLink(assemblyRoot.resolve("LinkedAssembly"), assemblyTarget);
        }
        catch (UnsupportedOperationException | IOException error) {
            return;
        }
        expectFailure(() -> Il2CppClassCatalog.scan(assemblyRoot), "symbolic links");
    }

    private static void rejectsSymlinkedRuleFile(Path directory) throws Exception {
        Path root = Files.createDirectory(directory.resolve("rule-link-source"));
        write(root, "Game/Class.cs");
        Path target = Files.writeString(directory.resolve("rule-target.txt"), "Game\n");
        Path link = directory.resolve("rule-link.txt");
        try {
            Files.createSymbolicLink(link, target);
        }
        catch (UnsupportedOperationException | IOException error) {
            return;
        }

        expectFailure(() -> Il2CppClassSelector.select(Il2CppClassCatalog.scan(root),
                Il2CppExportScope.BLACKLIST, List.of(), List.of(), link), "regular file");
    }

    private static void rejectsMalformedRuleFile(Path directory) throws Exception {
        Path root = Files.createDirectory(directory.resolve("malformed-rule-source"));
        write(root, "Game/Class.cs");
        Path rules = directory.resolve("malformed-rules.txt");
        Files.write(rules, new byte[] { (byte) 0xc3, (byte) 0x28 });

        expectFailure(() -> Il2CppClassSelector.select(Il2CppClassCatalog.scan(root),
                Il2CppExportScope.BLACKLIST, List.of(), List.of(), rules), "not valid UTF-8");
    }

    private static void rejectsLongRule(Path directory) throws Exception {
        Path root = Files.createDirectory(directory.resolve("long-rule-source"));
        write(root, "Game/Class.cs");
        Path rules = directory.resolve("long-rule.txt");
        Files.writeString(rules, "A".repeat(257), StandardCharsets.UTF_8);

        expectFailure(() -> Il2CppClassSelector.select(Il2CppClassCatalog.scan(root),
                Il2CppExportScope.BLACKLIST, List.of(), List.of(), rules),
                "exceeds 256 characters");
    }

    private static void rejectsOversizedRuleFiles(Path directory) throws Exception {
        Path root = Files.createDirectory(directory.resolve("large-rule-source"));
        write(root, "Game/Actor.cs");
        Path rules = directory.resolve("large-rules.txt");
        Files.writeString(rules, "A".repeat(1024 * 1024 + 1), StandardCharsets.UTF_8);

        expectFailure(() -> Il2CppClassSelector.select(Il2CppClassCatalog.scan(root),
                Il2CppExportScope.BLACKLIST, List.of(), List.of(), rules), "exceeds 1 MiB");
    }

    private static Path write(Path root, String relative) throws IOException {
        Path path = root.resolve(relative);
        Files.createDirectories(path.getParent());
        return Files.writeString(path, "public class Fixture {}\n", StandardCharsets.UTF_8);
    }

    private static void expectFailure(CheckedRunnable action, String message) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected failure containing: " + message);
        }
        catch (IOException error) {
            check(error.getMessage().contains(message), "error message: " + error.getMessage());
        }
    }

    private static void deleteTree(Path root) throws IOException {
        try (var paths = Files.walk(root)) {
            for (Path path : paths.sorted((left, right) -> right.compareTo(left)).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    @FunctionalInterface
    private interface CheckedRunnable {
        void run() throws Exception;
    }
}
