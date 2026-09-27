// Verifies conversion of a stored delegate signature to a Ghidra prototype.
// @category Test

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.VoidDataType;
import turboheader.il2cpp.analysis.delegatecall.GhidraDelegatePrototypeResolver;
import turboheader.il2cpp.analysis.delegatecall.Il2CppDelegatePrototypeCatalog;

public class VerifyTurboHeaderDelegatePrototype extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var catalog = Il2CppDelegatePrototypeCatalog.read(currentProgram).orElseThrow();
        var prototype = catalog.forTypeId(7).orElseThrow();
        int transaction = currentProgram.startTransaction("delegate prototype fixture types");
        boolean commit = false;
        try {
            var signature = GhidraDelegatePrototypeResolver.resolve(
                    currentProgram, prototype);
            var arguments = signature.getArguments();
            require(arguments.length == 3, "delegate argument count");
            require(arguments[0].getDataType().getName().equals("Il2CppMethodPointer"),
                    "delegate method-code type");
            require(arguments[1].getDataType().getLength() == Integer.BYTES,
                    "delegate managed argument type");
            require(arguments[2].getDataType() instanceof Pointer,
                    "delegate MethodInfo pointer type");
            require(signature.getReturnType().isEquivalent(VoidDataType.dataType),
                    "delegate return type");
            var convention = currentProgram.getCompilerSpec().getDefaultCallingConvention();
            require(convention == null || convention.getName().equals(
                    signature.getCallingConventionName()),
                    "delegate calling convention");
            commit = true;
        }
        finally {
            currentProgram.endTransaction(transaction, commit);
        }
        println("TurboHeader delegate prototype conversion verification passed");
    }

    private static void require(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }
}
