// @category Data Types

import java.nio.file.Path;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import turboheader.il2cpp.Il2CppClassCatalog;
import turboheader.il2cpp.Il2CppDecompilationCoordinator;
import turboheader.il2cpp.analysis.Il2CppExportAnalysisService;
import turboheader.il2cpp.Il2CppExportPlanner;
import turboheader.il2cpp.Il2CppFunctionPreparationService;

public class VerifyTurboHeaderExportAnalysis extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var before = Il2CppExportAnalysisService.analyzeBeforePreparation(
                currentProgram, null, monitor);
        boolean aarch64 = currentProgram.getLanguage().getProcessor().toString()
                .equalsIgnoreCase("AARCH64");
        require(before.profile().customNoreturn() == aarch64,
                "noreturn selection does not match the processor");
        require(before.noreturn().isPresent() == aarch64,
                "custom noreturn result does not match the selected analysis");
        if (!aarch64) {
            require(before.profile().enabledAnalyzers().contains(
                    "Non-Returning Functions - Discovered"),
                    "Ghidra noreturn fallback is disabled");
        }

        Function function = firstInternalFunction();
        var ready = new Il2CppFunctionPreparationService.PreparedFunction(function, function);
        var classPlan = classPlan(function);
        var preparedClass = new Il2CppFunctionPreparationService.PreparedClassPlan(
                classPlan, List.of(ready));
        var preparation = new Il2CppFunctionPreparationService.PreparationResult(
                List.of(preparedClass), List.of(ready), 1, 0, 0);

        var after = Il2CppExportAnalysisService.analyzeAfterPreparation(
                currentProgram, preparation, monitor);
        require(after.helpers().selectedFunctions() == 1,
                "helper analysis did not receive the prepared function");
        require(after.stableModificationNumber() == currentProgram.getModificationNumber(),
                "stable modification marker differs from the program");

        long stableModification = after.stableModificationNumber();
        Il2CppDecompilationCoordinator.decompile(currentProgram, preparation, 1, monitor);
        require(currentProgram.getModificationNumber() == stableModification,
                "decompilation changed the stable program");

        println("TurboHeader real-Ghidra export analysis verification passed");
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

    private static Il2CppExportPlanner.ClassPlan classPlan(Function function) {
        var entry = new Il2CppClassCatalog.ClassEntry(
                "Fixture.Analysis", "Analysis.cs", Path.of("fixtures", "Analysis.cs"));
        return new Il2CppExportPlanner.ClassPlan(
                entry, Path.of("Fixture", "Analysis.cpp"), List.of(function));
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
