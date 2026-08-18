// Verifies that imported method signatures retain the program's default ABI.
// @category Data Types

import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import turboheader.il2cpp.GhidraMethodImporter;
import turboheader.il2cpp.ScriptMethodReader.ScriptMethod;

public class VerifyTurboHeaderCallingConvention extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var convention = currentProgram.getCompilerSpec().getDefaultCallingConvention();
        require(convention != null, "program has no default calling convention");

        var functions = currentProgram.getFunctionManager().getFunctions(true);
        require(functions.hasNext(), "program has no function for signature verification");
        Function function = functions.next();
        long offset = function.getEntryPoint().subtract(currentProgram.getImageBase());
        require(offset >= 0, "test function precedes the image base");

        var method = new ScriptMethod(offset, "TurboHeaderCallingConventionFixture",
                "void TurboHeaderCallingConventionFixture (void* value);", "vi", null);
        var stats = new GhidraMethodImporter(currentProgram, monitor).importMethods(List.of(method));
        require(stats.applied() == 1 && stats.failed() == 0,
                "method signature import failed: " + stats.failureCounts());

        Function imported = currentProgram.getFunctionManager().getFunctionAt(function.getEntryPoint());
        require(imported != null, "imported function is missing");
        require(convention.getName().equals(imported.getCallingConventionName()),
                "calling convention differs: expected " + convention.getName() + ", got " +
                imported.getCallingConventionName());
        println("TurboHeader calling-convention verification passed: " + convention.getName());
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
