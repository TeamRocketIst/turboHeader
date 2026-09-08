// Verifies the Java class/function matcher against a real Ghidra Function.
// @category Data Types

import java.nio.file.Path;
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
        Function function = firstInternalFunction();
        function.setName("TurboHeaderFixtureActor__Run", SourceType.USER_DEFINED);
        function.setComment(MethodAssemblyIdentity.write(function.getComment(), "Fixture.Two"));

        var first = entry("Fixture.One");
        var second = entry("Fixture.Two");
        var result = GhidraFunctionMatcher.match(currentProgram, List.of(first, second), monitor);

        require(result.functionsByClass().get(first).isEmpty(), "wrong assembly matched");
        require(result.functionsByClass().get(second).contains(function), "function was not matched");
        require(result.assemblyAmbiguitiesResolved() == 1, "assembly ambiguity was not resolved");
        println("TurboHeader real-Ghidra function matcher verification passed");
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

    private static Il2CppClassCatalog.ClassEntry entry(String assembly) {
        return new Il2CppClassCatalog.ClassEntry(
                assembly, "TurboHeaderFixtureActor.cs",
                Path.of("synthetic", assembly, "TurboHeaderFixtureActor.cs"));
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
