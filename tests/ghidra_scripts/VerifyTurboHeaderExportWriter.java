// @category Data Types

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import turboheader.il2cpp.HeadlessRequestReader;
import turboheader.il2cpp.exporting.Il2CppClassCatalog;
import turboheader.il2cpp.exporting.Il2CppClassSelector;
import turboheader.il2cpp.Il2CppExportPlanner;
import turboheader.il2cpp.Il2CppExportScope;
import turboheader.il2cpp.exporting.Il2CppExportWriter;
import turboheader.il2cpp.decompile.Il2CppDecompilationCoordinator;
import turboheader.il2cpp.decompile.Il2CppFunctionMatcher;
import turboheader.il2cpp.decompile.Il2CppFunctionPreparationService;

public class VerifyTurboHeaderExportWriter extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Path root = Files.createTempDirectory("turboheader-export-writer-");
        try {
            verifySuccessfulOutput(root.resolve("successful"));
            verifyFailureOutput(root.resolve("failure"));
            verifyTraversalRejected(root.resolve("traversal"));
            verifySymlinkRejected(root.resolve("symlink"), root.resolve("outside"));
            println("TurboHeader real-Ghidra export writer verification passed");
        }
        finally {
            deleteTree(root);
        }
    }

    private void verifySuccessfulOutput(Path output) throws Exception {
        Function function = firstInternalFunction();
        var matched = classPlan("Fixture.Core", "Output.cs", List.of(function));
        var empty = classPlan("Fixture.Empty", "Empty.cs", List.of());
        var ready = new Il2CppFunctionPreparationService.PreparedFunction(function, function);
        var preparation = new Il2CppFunctionPreparationService.PreparationResult(
                List.of(
                        new Il2CppFunctionPreparationService.PreparedClassPlan(
                                matched, List.of(ready)),
                        new Il2CppFunctionPreparationService.PreparedClassPlan(
                                empty, List.of())),
                List.of(ready), 1, 0, 0);
        var decompilation = Il2CppDecompilationCoordinator.decompile(
                currentProgram, preparation, 1, monitor);
        var plan = exportPlan(output, List.of(matched, empty),
                List.of(empty.classEntry()), List.of(new Il2CppFunctionMatcher.Ambiguity(
                        0x1000, "Fixture_Ambiguous", "fixture_ambiguous",
                        List.of("Fixture.One", "Fixture.Two"))));
        var timings = new Il2CppExportWriter.PhaseTimings(
                1_000_000_000L, 2_000_000_000L, 3_000_000_000L,
                4_000_000_000L, 10_000_000_000L);

        long modification = currentProgram.getModificationNumber();
        var result = Il2CppExportWriter.write(
                currentProgram, plan, decompilation, timings, monitor);
        require(currentProgram.getModificationNumber() == modification,
                "writer modified the Ghidra program");
        require(result.classFiles() == 2, "class file count differs");
        require(result.completedFunctions() == 1, "completed function count differs");
        require(result.failedFunctions() == 0, "unexpected writer failure count");

        String classText = Files.readString(output.resolve("Fixture.Core/Output.cpp"));
        String code = ((Il2CppDecompilationCoordinator.DecompiledFunction)
                decompilation.classes().get(0).functions().get(0)).result().getCCode();
        require(classText.contains("// Function: "), "function heading is missing");
        require(classText.contains("// Address : " + function.getEntryPoint()),
                "function address is missing");
        require(classText.contains(code), "decompiled C output differs");

        String emptyText = Files.readString(output.resolve("Fixture.Empty/Empty.cpp"));
        require(emptyText.contains("No Ghidra functions matched"),
                "empty class explanation is missing");

        String summary = Files.readString(output.resolve("_export_summary.txt"));
        require(summary.contains("Classes selected: 2"), "summary class count differs");
        require(summary.contains("Functions matched/exported: 1"),
                "summary function count differs");
        require(summary.contains("Timing total export seconds: 10."),
                "summary total timing differs");
        require(Files.readString(output.resolve("_assembly_filter.txt"))
                .contains("[INCLUDE] Fixture.Core -- selected by whitelist"),
                "assembly report differs");
        require(Files.readString(output.resolve("_ambiguous_matches.txt"))
                .contains("Matched key: fixture_ambiguous"),
                "ambiguity report differs");
        require(Files.readString(output.resolve("_classes_with_no_matches.txt"))
                .contains("Fixture.Empty/Empty"), "unmatched class report differs");
    }

    private void verifyFailureOutput(Path output) throws Exception {
        Function function = firstInternalFunction();
        var classPlan = classPlan("Fixture.Failure", "Failure.cs", List.of(function));
        var failure = new Il2CppDecompilationCoordinator.FunctionFailure(
                function, Il2CppDecompilationCoordinator.FailureStage.PREPARATION,
                "synthetic failure\nsecond line", false, 0);
        var classResult = new Il2CppDecompilationCoordinator.DecompiledClassPlan(
                classPlan, List.of(failure));
        var decompilation = new Il2CppDecompilationCoordinator.DecompilationResult(
                List.of(classResult), List.of(failure), 0, Optional.empty());
        var plan = exportPlan(output, List.of(classPlan), List.of(), List.of());
        var timings = new Il2CppExportWriter.PhaseTimings(0, 0, 0, 0, 0);

        Il2CppExportWriter.write(currentProgram, plan, decompilation, timings, monitor);
        String text = Files.readString(output.resolve("Fixture.Failure/Failure.cpp"));
        require(text.contains("// Decompilation exception: synthetic failure second line\n"),
                "failure was not written as one safe comment line");
        require(!Files.exists(output.resolve("_ambiguous_matches.txt")),
                "empty ambiguity report was written");
        require(!Files.exists(output.resolve("_classes_with_no_matches.txt")),
                "empty unmatched-class report was written");
    }

    private void verifyTraversalRejected(Path output) throws Exception {
        var entry = new Il2CppClassCatalog.ClassEntry(
                "Fixture.Traversal", "Traversal.cs",
                Path.of("fixtures", "Traversal.cs"));
        try {
            new Il2CppExportPlanner.ClassPlan(
                    entry, Path.of("..", "escape.cpp"), List.of());
            throw new AssertionError("traversal output path was accepted");
        }
        catch (IllegalArgumentException expected) {
            // Expected.
        }
        require(!Files.exists(output), "invalid plan created the output root");
        require(!Files.exists(output.getParent().resolve("escape.cpp")),
                "traversal path escaped the output root");
    }

    private void verifySymlinkRejected(Path output, Path outside) throws Exception {
        Files.createDirectories(output);
        Files.createDirectories(outside);
        Path link = output.resolve("Fixture.Link");
        try {
            Files.createSymbolicLink(link, outside);
        }
        catch (UnsupportedOperationException | IOException error) {
            return;
        }

        Function function = firstInternalFunction();
        var classPlan = classPlan("Fixture.Link", "Escape.cs", List.of(function));
        var failure = new Il2CppDecompilationCoordinator.FunctionFailure(
                function, Il2CppDecompilationCoordinator.FailureStage.PREPARATION,
                "synthetic failure", false, 0);
        var decompilation = failedResult(classPlan, failure);
        var plan = exportPlan(output, List.of(classPlan), List.of(), List.of());

        expectWriteFailure(plan, decompilation);
        require(!Files.exists(outside.resolve("Escape.cpp")),
                "symlink path escaped the output root");
    }

    private void expectWriteFailure(Il2CppExportPlanner.ExportPlan plan,
            Il2CppDecompilationCoordinator.DecompilationResult decompilation)
            throws Exception {
        try {
            Il2CppExportWriter.write(currentProgram, plan, decompilation,
                    new Il2CppExportWriter.PhaseTimings(0, 0, 0, 0, 0), monitor);
            throw new AssertionError("unsafe output path was accepted");
        }
        catch (IOException expected) {
            // Expected.
        }
    }

    private static Il2CppDecompilationCoordinator.DecompilationResult failedResult(
            Il2CppExportPlanner.ClassPlan classPlan,
            Il2CppDecompilationCoordinator.FunctionFailure failure) {
        var classResult = new Il2CppDecompilationCoordinator.DecompiledClassPlan(
                classPlan, List.of(failure));
        return new Il2CppDecompilationCoordinator.DecompilationResult(
                List.of(classResult), List.of(failure), 0, Optional.empty());
    }

    private Il2CppExportPlanner.ExportPlan exportPlan(Path output,
            List<Il2CppExportPlanner.ClassPlan> classes,
            List<Il2CppClassCatalog.ClassEntry> unmatched,
            List<Il2CppFunctionMatcher.Ambiguity> ambiguities) {
        var request = new HeadlessRequestReader.ExportRequest(
                Path.of("fixtures"), output, Il2CppExportScope.WHITELIST,
                null, null, 1);
        Map<String, Il2CppClassSelector.AssemblyDecision> assemblies = new LinkedHashMap<>();
        for (var item : classes) {
            String assembly = item.classEntry().assembly();
            assemblies.putIfAbsent(assembly.toLowerCase(Locale.ROOT),
                    new Il2CppClassSelector.AssemblyDecision(
                            assembly, true, "selected by whitelist"));
        }
        int matched = classes.stream().mapToInt(item -> item.functions().size()).sum();
        return new Il2CppExportPlanner.ExportPlan(request, classes, unmatched, ambiguities,
                assemblies, classes.size(), 10, matched, 0, 0);
    }

    private static Il2CppExportPlanner.ClassPlan classPlan(String assembly, String source,
            List<Function> functions) {
        var entry = new Il2CppClassCatalog.ClassEntry(
                assembly, source, Path.of("fixtures", assembly, source));
        return new Il2CppExportPlanner.ClassPlan(
                entry, Path.of(assembly, source.replace(".cs", ".cpp")), functions);
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

    private static void deleteTree(Path root) throws Exception {
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
