// Verifies that a delegate-call prototype override survives a project reopen.
// @category Test

import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SymbolType;
import turboheader.il2cpp.analysis.delegatecall.DelegateCallPrototype;
import turboheader.il2cpp.analysis.delegatecall.GhidraDelegatePrototypeResolver;
import turboheader.il2cpp.analysis.delegatecall.Il2CppDelegateCallAnalyzer;
import turboheader.il2cpp.analysis.delegatecall.Il2CppDelegateCallPublisher;

public class VerifyTurboHeaderDelegateCallOverride extends GhidraScript {
    private static final long DELEGATE_CALLER = 0x480;
    private static final String OBJECT_TYPE = "System_Action_int__o*";
    private static final String SIGNATURE =
            "void delegate_invoke (Il2CppMethodPointer methodCode, int32_t value, " +
            "const MethodInfo* method);";

    @Override
    protected void run() throws Exception {
        var stored = findStoredOverride();
        Function function = currentProgram.getFunctionManager()
                .getFunctionContaining(stored.callsite());
        require(function != null, "delegate caller is missing after project reopen");
        var callsite = stored.callsite();

        var proof = new Il2CppDelegateCallAnalyzer.ProvenCall(
                callsite, 7, OBJECT_TYPE, SIGNATURE);
        long before = currentProgram.getModificationNumber();
        var publication = Il2CppDelegateCallPublisher.publish(
                currentProgram, List.of(proof), monitor);
        require(publication.requested() == 1 && publication.added() == 0 &&
                publication.retained() == 1,
                "delegate prototype override did not survive project reopen");
        require(currentProgram.getModificationNumber() == before,
                "reopened delegate prototype publication changed the program");

        var decompiler = new DecompInterface();
        try {
            decompiler.toggleCCode(false);
            require(decompiler.openProgram(currentProgram),
                    "could not open reopened delegate-call fixture");
            require(decompiler.setSimplificationStyle("normalize"),
                    "could not normalize reopened delegate-call fixture");
            var result = decompiler.decompileFunction(function, 30, monitor);
            require(result.decompileCompleted() && result.getHighFunction() != null,
                    "could not decompile reopened delegate-call fixture");
            boolean indirect = false;
            var operations = result.getHighFunction().getPcodeOps();
            while (operations.hasNext()) {
                var operation = operations.next();
                if (operation.getSeqnum().getTarget().equals(callsite) &&
                        operation.getOpcode() == PcodeOp.CALLIND) {
                    indirect = true;
                }
            }
            require(indirect, "reopened delegate call is no longer indirect");
        }
        finally {
            decompiler.dispose();
        }
        verifyAtomicConflict(function);
        println("TurboHeader delegate-call override survived project reopen");
        println("TurboHeader delegate-call conflict rollback verification passed");
    }

    private void verifyAtomicConflict(Function delegateFunction) throws Exception {
        Function mismatch = currentProgram.getFunctionManager().getFunctionAt(
                delegateFunction.getEntryPoint().add(0x20));
        require(mismatch != null, "delegate mismatch caller is missing");
        Function pending = findFunction("Sample$$Run");
        require(pending != null, "pending indirect-call fixture is missing");
        var pendingCallsite = pending.getEntryPoint().add(0x48);
        var conflictingCallsite = mismatch.getEntryPoint().add(0x18);
        installConflictingOverride(mismatch, conflictingCallsite);

        var pendingProof = new Il2CppDelegateCallAnalyzer.ProvenCall(
                pendingCallsite, 7, OBJECT_TYPE, SIGNATURE);
        var conflictingProof = new Il2CppDelegateCallAnalyzer.ProvenCall(
                conflictingCallsite, 7, OBJECT_TYPE, SIGNATURE);
        boolean rejected = false;
        try {
            Il2CppDelegateCallPublisher.publish(currentProgram,
                    List.of(pendingProof, conflictingProof), monitor);
        }
        catch (IllegalStateException expected) {
            rejected = true;
        }
        require(rejected, "conflicting delegate prototype override was accepted");
        pending = currentProgram.getFunctionManager().getFunctionAt(
                pending.getEntryPoint());
        require(pending != null && overrideAt(pending, pendingCallsite) == null,
                "conflicting delegate publication partially changed the program");
    }

    private void installConflictingOverride(Function function, Address callsite)
            throws Exception {
        var prototype = DelegateCallPrototype.parse(7, OBJECT_TYPE,
                "void delegate_invoke (Il2CppMethodPointer methodCode, " +
                "int64_t value, const MethodInfo* method);");
        FunctionSignature signature = GhidraDelegatePrototypeResolver.resolve(
                currentProgram, prototype);
        HighFunctionDBUtil.writeOverride(function, callsite, signature);
        require(overrideAt(function, callsite) != null,
                "conflicting delegate prototype was not installed");
    }

    private Function findFunction(String name) {
        var functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            var function = functions.next();
            if (function.getName().equals(name)) {
                return function;
            }
        }
        return null;
    }

    private FunctionSignature overrideAt(Function function,
            Address callsite) {
        var namespace = HighFunction.findOverrideSpace(function);
        if (namespace == null) {
            return null;
        }
        FunctionSignature result = null;
        for (var symbol : currentProgram.getSymbolTable().getSymbols(callsite)) {
            if (symbol.getSymbolType() != SymbolType.LABEL ||
                    !symbol.getParentNamespace().equals(namespace) ||
                    !symbol.getName().startsWith("prt")) {
                continue;
            }
            DataTypeSymbol stored = HighFunctionDBUtil.readOverride(symbol);
            require(stored != null &&
                    stored.getDataType() instanceof FunctionSignature,
                    "invalid delegate prototype override");
            require(result == null, "multiple delegate prototype overrides");
            result = (FunctionSignature) stored.getDataType();
        }
        return result;
    }

    private StoredOverride findStoredOverride() {
        var block = currentProgram.getMemory().getBlock("interface_dispatch");
        require(block != null, "delegate fixture block is missing after project reopen");
        Address callsite = block.getStart().add(DELEGATE_CALLER + 0x14);
        Function function = currentProgram.getFunctionManager()
                .getFunctionContaining(callsite);
        require(function != null, "delegate fixture is missing after project reopen");
        FunctionSignature signature = overrideAt(function, callsite);
        require(signature != null && signature.getArguments().length == 3 &&
                signature.getArguments()[1].getDataType().getLength() == Integer.BYTES,
                "delegate prototype override is missing after project reopen");
        return new StoredOverride(callsite);
    }

    private record StoredOverride(Address callsite) {
    }

    private static void require(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }
}
