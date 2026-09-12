// @category Data Types

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import turboheader.il2cpp.Il2CppClassCatalog;
import turboheader.il2cpp.Il2CppExportPlanner;
import turboheader.il2cpp.decompile.Il2CppDecompilationCoordinator;
import turboheader.il2cpp.decompile.Il2CppFunctionPreparationService;

public class VerifyTurboHeaderDecompilationCoordinator extends GhidraScript {
    @Override
    protected void run() throws Exception {
        List<Function> functions = firstInternalFunctions(2);
        Function lower = functions.get(0);
        Function upper = functions.get(1);
        var ready = new Il2CppFunctionPreparationService.PreparedFunction(lower, lower);
        var failed = new Il2CppFunctionPreparationService.FailedFunction(
                upper, "synthetic preparation failure");

        var firstClass = classPlan("Fixture.One", "First.cs", List.of(lower, upper));
        var secondClass = classPlan("Fixture.Two", "Second.cs", List.of(lower));
        var preparedFirst = new Il2CppFunctionPreparationService.PreparedClassPlan(
                firstClass, List.of(ready, failed));
        var preparedSecond = new Il2CppFunctionPreparationService.PreparedClassPlan(
                secondClass, List.of(ready));
        var preparation = new Il2CppFunctionPreparationService.PreparationResult(
                List.of(preparedFirst, preparedSecond), List.of(ready, failed), 3, 1, 0);

        long modification = currentProgram.getModificationNumber();
        var result = Il2CppDecompilationCoordinator.decompile(
                currentProgram, preparation, 2, monitor);

        require(currentProgram.getModificationNumber() == modification,
                "decompilation changed the Ghidra program");
        require(result.submittedFunctions() == 1, "submission count differs");
        require(result.completedFunctions() == 1, "completed count differs");
        require(result.failedFunctions() == 1, "failure count differs");
        require(result.batch().isPresent(), "decompiler batch is missing");
        require(result.batch().orElseThrow().getWorkerCount() == 2, "worker count differs");
        require(result.addressOrder().get(0) instanceof
                Il2CppDecompilationCoordinator.DecompiledFunction,
                "prepared function was not decompiled");
        var completed = (Il2CppDecompilationCoordinator.DecompiledFunction)
                result.addressOrder().get(0);
        require(!completed.result().getCCode().isBlank(), "decompiler returned empty C output");
        require(result.addressOrder().get(1) instanceof
                Il2CppDecompilationCoordinator.FunctionFailure failure &&
                failure.stage() == Il2CppDecompilationCoordinator.FailureStage.PREPARATION,
                "preparation failure was not retained");
        require(result.classes().get(0).functions().get(0) ==
                result.classes().get(1).functions().get(0),
                "duplicate class slot did not reuse its decompilation result");

        var failedClass = new Il2CppFunctionPreparationService.PreparedClassPlan(
                firstClass, List.of(failed));
        var failedPreparation = new Il2CppFunctionPreparationService.PreparationResult(
                List.of(failedClass), List.of(failed), 1, 1, 0);
        var failedResult = Il2CppDecompilationCoordinator.decompile(
                currentProgram, failedPreparation, 2, monitor);
        require(failedResult.submittedFunctions() == 0, "failed function was submitted");
        require(failedResult.batch().isEmpty(), "empty submission opened a decompiler batch");

        expectInvalidWorkers(preparation, 0);
        expectInvalidWorkers(preparation, 13);

        println("TurboHeader real-Ghidra decompilation coordinator verification passed");
    }

    private void expectInvalidWorkers(
            Il2CppFunctionPreparationService.PreparationResult preparation, int workers)
            throws Exception {
        try {
            Il2CppDecompilationCoordinator.decompile(
                    currentProgram, preparation, workers, monitor);
            throw new AssertionError("invalid worker count was accepted");
        }
        catch (IllegalArgumentException expected) {
            // expected
        }
    }

    private List<Function> firstInternalFunctions(int count) {
        List<Function> functions = new ArrayList<>();
        var iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext() && functions.size() < count) {
            Function function = iterator.next();
            if (!function.isExternal()) {
                functions.add(function);
            }
        }
        require(functions.size() == count, "fixture has too few internal functions");
        functions.sort((left, right) -> Long.compareUnsigned(
                left.getEntryPoint().getUnsignedOffset(),
                right.getEntryPoint().getUnsignedOffset()));
        return functions;
    }

    private static Il2CppExportPlanner.ClassPlan classPlan(String assembly, String file,
            List<Function> functions) {
        var entry = new Il2CppClassCatalog.ClassEntry(
                assembly, file, Path.of("fixtures", assembly, file));
        return new Il2CppExportPlanner.ClassPlan(entry,
                Path.of(assembly, file.replace(".cs", ".cpp")), functions);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
