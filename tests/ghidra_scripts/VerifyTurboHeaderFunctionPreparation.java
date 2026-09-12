// @category Data Types

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import turboheader.il2cpp.HeadlessRequestReader;
import turboheader.il2cpp.Il2CppClassCatalog;
import turboheader.il2cpp.Il2CppExportPlanner;
import turboheader.il2cpp.Il2CppExportScope;
import turboheader.il2cpp.decompile.Il2CppFunctionPreparationService;

public class VerifyTurboHeaderFunctionPreparation extends GhidraScript {
    @Override
    protected void run() throws Exception {
        List<Function> functions = firstInternalFunctions(2);
        Function lower = functions.get(0);
        Function upper = functions.get(1);
        var firstClass = classPlan("Fixture.One", "First.cs", List.of(upper, lower));
        var secondClass = classPlan("Fixture.Two", "Second.cs", List.of(lower));

        var result = Il2CppFunctionPreparationService.prepare(
                currentProgram, exportPlan(List.of(firstClass, secondClass)), monitor);

        require(result.functionReferences() == 3, "function reference count differs");
        require(result.uniqueFunctions() == 2, "function deduplication differs");
        require(result.preparedFunctions() == 2, "function preparation failed");
        require(result.failedFunctions() == 0, "unexpected preparation failure");
        require(result.addressOrder().get(0).displayFunction().equals(lower),
                "functions were not prepared in address order");
        require(result.addressOrder().get(1).displayFunction().equals(upper),
                "functions were not prepared in address order");
        require(result.classes().get(0).functions().get(1) ==
                result.classes().get(1).functions().get(0),
                "duplicate function did not share one preparation outcome");
        for (var outcome : result.addressOrder()) {
            require(outcome instanceof Il2CppFunctionPreparationService.PreparedFunction,
                    "prepared function has no usable result");
            require(currentProgram.getListing().getInstructionAt(
                    outcome.displayFunction().getEntryPoint()) != null,
                    "prepared function has no entry instruction");
        }

        println("TurboHeader real-Ghidra function preparation verification passed");
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

    private static Il2CppExportPlanner.ExportPlan exportPlan(
            List<Il2CppExportPlanner.ClassPlan> classes) {
        var request = new HeadlessRequestReader.ExportRequest(
                Path.of("fixtures"), Path.of("output"), Il2CppExportScope.WHITELIST,
                null, null, 2);
        return new Il2CppExportPlanner.ExportPlan(
                request, classes, List.of(), List.of(), Map.of(),
                classes.size(), 2, 2, 0, 0);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
