// @category Data Types

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import turboheader.il2cpp.HeadlessRequestReader;
import turboheader.il2cpp.Il2CppExportPlanner;
import turboheader.il2cpp.Il2CppExportPipeline;
import turboheader.il2cpp.Il2CppExportScope;
import turboheader.il2cpp.metadata.MethodAssemblyIdentity;

public class VerifyTurboHeaderExportPlanner extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Path root = Files.createTempDirectory("turboheader-export-plan-");
        try {
            verifyPlan(root);
            verifyOutcomeReporting();
            verifyAmbiguousExport(root);
            println("TurboHeader real-Ghidra export planner verification passed");
            println("TurboHeader ambiguous export warning verification passed");
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

    private void verifyOutcomeReporting() {
        var warnings = new ArrayList<String>();
        Il2CppExportPipeline.reportOutcome(0, 0, warnings::add);
        require(warnings.isEmpty(), "clean export produced a warning");
        Il2CppExportPipeline.reportOutcome(0, 2, warnings::add);
        require(warnings.size() == 1 && warnings.get(0).startsWith("WARNING: TurboHeader ") &&
                warnings.get(0).contains("ambiguous methods: 2") && warnings.get(0).contains("_ambiguous_matches.txt"),
                "ambiguous export did not produce one warning");
        for (int ambiguous : new int[] { 0, 2 }) {
            try {
                Il2CppExportPipeline.reportOutcome(1, ambiguous, warnings::add);
                throw new AssertionError("lost function body was not fatal");
            }
            catch (IllegalStateException expected) {
                require(expected.getMessage().contains("lost 1 function bodies"),
                        "export failed for an unexpected reason");
            }
        }
        require(warnings.size() == 1, "failed export was reduced to a warning");
    }

    private void verifyAmbiguousExport(Path root) throws Exception {
        Function function = firstInternalFunction();
        String comment = function.getComment();
        Path output = root.resolve("ambiguous-output");
        var request = new JsonObject();
        request.addProperty("schema", 1);
        request.addProperty("operation", "export");
        request.addProperty("classSource", root.resolve("classes").toString());
        request.addProperty("output", output.toString());
        request.addProperty("scope", "all");
        request.add("frameworkRules", JsonNull.INSTANCE);
        request.add("noreturnSeeds", JsonNull.INSTANCE);
        request.addProperty("decompileJobs", 1);
        Path manifest = root.resolve("ambiguous-request.json");
        Files.writeString(manifest, request.toString());
        try {
            function.setComment(null);
            runScript("ExportIl2Cpp.java", new String[] { "--request", manifest.toString() });
            String summary = Files.readString(output.resolve("_export_summary.txt"));
            require(summary.contains("Ambiguous functions skipped: 1"), "ambiguity count was lost");
            require(summary.contains("Functions failed to decompile: 0"), "unexpected decompilation failure");
            require(Files.readString(output.resolve("_ambiguous_matches.txt"))
                    .contains("TurboHeaderPlanFixture"), "ambiguity details were not written");
        }
        finally {
            function.setComment(comment);
        }
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
