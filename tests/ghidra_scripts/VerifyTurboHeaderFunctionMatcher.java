// Verifies the Java class/function matcher against a real Ghidra Function.
// @category Data Types

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import turboheader.il2cpp.GhidraFunctionMatcher;
import turboheader.il2cpp.Il2CppClassCatalog;
import turboheader.il2cpp.MethodAssemblyIdentity;

public class VerifyTurboHeaderFunctionMatcher extends GhidraScript {
    @Override
    protected void run() throws Exception {
        List<Function> functions = internalFunctions(3);
        Function function = functions.get(0);
        function.setName("TurboHeaderFixtureActor__Run", SourceType.USER_DEFINED);
        function.setComment(MethodAssemblyIdentity.write(function.getComment(), "Fixture.Two"));

        var first = entry("Fixture.One");
        var second = entry("Fixture.Two");
        var result = GhidraFunctionMatcher.match(currentProgram, List.of(first, second), monitor);

        require(result.functionsByClass().get(first).isEmpty(), "wrong assembly matched");
        require(result.functionsByClass().get(second).contains(function), "function was not matched");
        require(result.assemblyAmbiguitiesResolved() == 1, "assembly ambiguity was not resolved");

        Function upperFunction = functions.get(1);
        Function lowerFunction = functions.get(2);
        upperFunction.setName("U__Start", SourceType.USER_DEFINED);
        lowerFunction.setName("u__Stop", SourceType.USER_DEFINED);
        var upper = entry("Fixture.Case", "U.cs");
        var lower = entry("Fixture.Case", "u.cs");
        var caseResult = GhidraFunctionMatcher.match(
                currentProgram, List.of(upper, lower), monitor);

        require(caseResult.functionsByClass().get(upper).equals(List.of(upperFunction)),
                "uppercase function was not matched");
        require(caseResult.functionsByClass().get(lower).equals(List.of(lowerFunction)),
                "lowercase function was not matched");
        require(caseResult.ambiguities().isEmpty(), "exact-case match was ambiguous");
        println("TurboHeader real-Ghidra function matcher verification passed");
    }

    private List<Function> internalFunctions(int count) {
        List<Function> result = new ArrayList<>();
        var functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext() && result.size() < count) {
            Function function = functions.next();
            if (!function.isExternal()) {
                result.add(function);
            }
        }
        if (result.size() != count) {
            throw new AssertionError("fixture has too few internal functions");
        }
        return result;
    }

    private static Il2CppClassCatalog.ClassEntry entry(String assembly) {
        return new Il2CppClassCatalog.ClassEntry(
                assembly, "TurboHeaderFixtureActor.cs",
                Path.of("synthetic", assembly, "TurboHeaderFixtureActor.cs"));
    }

    private static Il2CppClassCatalog.ClassEntry entry(String assembly, String relative) {
        return new Il2CppClassCatalog.ClassEntry(
                assembly, relative, Path.of("synthetic", assembly, relative));
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
