// @category Data Types

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import turboheader.il2cpp.HeadlessRequestReader;
import turboheader.il2cpp.Il2CppExportPlanner;
import turboheader.il2cpp.Il2CppExportScope;
import turboheader.il2cpp.MethodAssemblyIdentity;

public class VerifyTurboHeaderExportPlanner extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Path root = Files.createTempDirectory("turboheader-export-plan-");
        try {
            verifyPlan(root);
            println("TurboHeader real-Ghidra export planner verification passed");
        }
        finally {
            deleteTree(root);
        }
    }

    private void verifyPlan(Path root) throws Exception {
        Function function = firstInternalFunction();
        function.setName("TurboHeaderPlanFixture__Run", SourceType.USER_DEFINED);
        function.setComment(MethodAssemblyIdentity.write(function.getComment(), "Fixture.Two"));

        Path source = Files.createDirectory(root.resolve("classes"));
        writeClass(source, "Fixture.One/TurboHeaderPlanFixture.cs");
        writeClass(source, "Fixture.Two/TurboHeaderPlanFixture.cs");
        Path output = root.resolve("output");
        var request = new HeadlessRequestReader.ExportRequest(source, output,
                Il2CppExportScope.WHITELIST, null, null, 8);
        var plan = Il2CppExportPlanner.plan(currentProgram, request, monitor);

        require(plan.discoveredClasses() == 2, "class count differs");
        require(plan.classes().size() == 2, "planned class count differs");
        require(plan.unmatchedClasses().size() == 1, "unmatched class count differs");
        var matched = plan.classes().stream()
                .filter(item -> item.classEntry().assembly().equals("Fixture.Two"))
                .findFirst().orElseThrow();
        require(matched.functions().equals(List.of(function)), "matched function differs");
        require(matched.relativeOutput().equals(
                Path.of("Fixture.Two", "TurboHeaderPlanFixture.cpp")),
                "output path differs");
        require(!Files.exists(output), "planner wrote the output directory");
    }

    private Function firstInternalFunction() {
        var functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (!function.isExternal()) {
                return function;
            }
        }
        throw new AssertionError("fixture has no internal function");
    }

    private static void writeClass(Path root, String relative) throws IOException {
        Path path = root.resolve(relative);
        Files.createDirectories(path.getParent());
        Files.writeString(path, "public class Fixture {}\n");
    }

    private static void deleteTree(Path root) throws IOException {
        try (var paths = Files.walk(root)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
