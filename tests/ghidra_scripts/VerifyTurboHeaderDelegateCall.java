// Verifies exact delegate-call proof over typed P-code.
// @category Test

import java.util.List;
import java.util.Optional;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SymbolType;
import turboheader.il2cpp.analysis.delegatecall.Il2CppDelegateCallAnalyzer;
import turboheader.il2cpp.analysis.delegatecall.Il2CppDelegateFieldLayout;
import turboheader.il2cpp.analysis.delegatecall.Il2CppDelegateCallPublisher;
import turboheader.il2cpp.analysis.delegatecall.Il2CppDelegatePrototypeCatalog;
import turboheader.il2cpp.metadata.GhidraMethodImporter;
import turboheader.il2cpp.metadata.ScriptMethodReader;
import turboheader.il2cpp.types.GhidraTypeImporter;

public class VerifyTurboHeaderDelegateCall extends GhidraScript {
    private static final long DELEGATE_CALLER = 0x480;
    private static final long MISMATCH_CALLER = 0x4a0;
    private static final long TAIL_CALLER = 0x4c0;
    private static final String OBJECT_TYPE = "System_Action_int__o*";
    private static final String SIGNATURE =
            "void delegate_invoke (Il2CppMethodPointer methodCode, int32_t value, " +
            "const MethodInfo* method);";

    @Override
    protected void run() throws Exception {
        var block = currentProgram.getMemory().getBlock("interface_dispatch");
        require(block != null, "delegate-call fixture block is missing");
        long blockOffset = block.getStart().subtract(currentProgram.getImageBase());
        installDelegateTypes();

        Address positiveEntry = currentProgram.getImageBase().add(
                Math.addExact(blockOffset, DELEGATE_CALLER));
        Address mismatchEntry = currentProgram.getImageBase().add(
                Math.addExact(blockOffset, MISMATCH_CALLER));
        Address tailEntry = currentProgram.getImageBase().add(
                Math.addExact(blockOffset, TAIL_CALLER));
        Function positive = createFixtureFunction(positiveEntry, "delegate caller");
        Function mismatch = createFixtureFunction(mismatchEntry, "delegate mismatch caller");
        Function tail = createFixtureFunction(tailEntry, "delegate tail caller");
        applySignatures(blockOffset);

        var layout = Il2CppDelegateFieldLayout.read(currentProgram).orElseThrow();
        require(layout.invokeTargetOffset() == 24 && layout.methodInfoOffset() == 40 &&
                layout.methodCodeOffset() == 64,
                "delegate offsets were not recovered from imported datatypes");
        var catalog = Il2CppDelegatePrototypeCatalog.read(currentProgram);
        long modificationNumber = currentProgram.getModificationNumber();
        var result = Il2CppDelegateCallAnalyzer.analyze(
                currentProgram, List.of(positive, mismatch), catalog, monitor);

        require(result.outcome() == Il2CppDelegateCallAnalyzer.Outcome.COMPLETE,
                "delegate-call analysis did not complete");
        require(result.candidateFunctions() == 2 && result.completedFunctions() == 2 &&
                result.failedFunctions() == 0, "delegate candidate statistics differ");
        require(result.indirectCalls() == 2 && result.delegateCandidates() == 2 &&
                result.shapeRejected() == 0, "delegate P-code statistics differ");
        require(result.provenCalls() == 1 && result.proofs().size() == 1,
                "exact delegate call was not proven");
        require(result.proofs().getFirst().callsite().equals(positiveEntry.add(0x14)) &&
                result.proofs().getFirst().typeId() == 7 &&
                result.proofs().getFirst().objectType().equals("System_Action_int__o*"),
                "delegate proof differs");
        require(result.rejections().objectMismatch() == 1 &&
                result.rejections().total() == 1 &&
                result.rejectionSamples().size() == 1 &&
                result.rejectionSamples().getFirst().callsite().equals(
                        mismatchEntry.add(0x18)),
                "mismatched delegate objects were not rejected");
        require(currentProgram.getModificationNumber() == modificationNumber,
                "delegate-call analysis changed the Ghidra program");

        for (int workers : new int[] { 1, 2, 4 }) {
            var parallel = Il2CppDelegateCallAnalyzer.analyze(currentProgram,
                    List.of(positive, mismatch, positive), catalog, workers, monitor);
            require(parallel.outcome() == result.outcome() &&
                    parallel.candidateFunctions() == result.candidateFunctions() &&
                    parallel.completedFunctions() == result.completedFunctions() &&
                    parallel.failedFunctions() == result.failedFunctions() &&
                    parallel.indirectCalls() == result.indirectCalls() &&
                    parallel.delegateCandidates() == result.delegateCandidates() &&
                    parallel.shapeRejected() == result.shapeRejected() &&
                    parallel.provenCalls() == result.provenCalls() &&
                    parallel.rejections().equals(result.rejections()) &&
                    parallel.rejectionSamples().equals(result.rejectionSamples()) &&
                    parallel.proofs().equals(result.proofs()),
                    "delegate worker results differ for " + workers + " workers");
            require(currentProgram.getModificationNumber() == modificationNumber,
                    "delegate workers changed the Ghidra program");
        }
        println("TurboHeader delegate worker parity verification passed");

        Address positiveCallsite = positiveEntry.add(0x14);
        Address tailCallsite = tailEntry.add(0x14);
        verifyRawTailCall(tailCallsite);
        var tailProof = new Il2CppDelegateCallAnalyzer.ProvenCall(
                tailCallsite, 7, OBJECT_TYPE, SIGNATURE);
        var published = Il2CppDelegateCallPublisher.publish(
                currentProgram, List.of(result.proofs().getFirst(), tailProof), monitor);
        require(published.requested() == 2 && published.added() == 2 &&
                published.retained() == 0,
                "delegate prototype publication statistics differ");
        verifyPublishedOverride(positive, positiveCallsite);
        verifyPublishedOverride(tail, tailCallsite);

        long beforeRepeat = currentProgram.getModificationNumber();
        var repeated = Il2CppDelegateCallPublisher.publish(
                currentProgram, List.of(result.proofs().getFirst(), tailProof), monitor);
        require(repeated.requested() == 2 && repeated.added() == 0 &&
                repeated.retained() == 2,
                "delegate prototype publication is not idempotent");
        require(currentProgram.getModificationNumber() == beforeRepeat,
                "repeated delegate prototype publication changed the program");
        println("TurboHeader delegate-call P-code proof verification passed");
        println("TurboHeader delegate-call override verification passed");
    }

    private void installDelegateTypes() {
        var manager = currentProgram.getDataTypeManager();
        DataType word = Undefined8DataType.dataType;
        var flatObject = new StructureDataType(
                GhidraTypeImporter.ROOT, "System_Delegate_o", 88, manager);
        flatObject.setPackingEnabled(false);
        flatObject.replaceAtOffset(0, new PointerDataType(null, 8, manager),
                -1, "klass", null);
        flatObject.replaceAtOffset(8, new PointerDataType(null, 8, manager),
                -1, "monitor", null);
        flatObject.replaceAtOffset(16, word, -1, "method_ptr", null);
        flatObject.replaceAtOffset(24, word, -1, "invoke_impl", null);
        flatObject.replaceAtOffset(32, word, -1, "m_target", null);
        flatObject.replaceAtOffset(40, word, -1, "method", null);
        flatObject.replaceAtOffset(48, word, -1, "delegate_trampoline", null);
        flatObject.replaceAtOffset(56, word, -1, "extra_arg", null);
        flatObject.replaceAtOffset(64, word, -1, "method_code", null);
        manager.addDataType(flatObject, DataTypeConflictHandler.REPLACE_HANDLER);
        var flatLayout = Il2CppDelegateFieldLayout.read(currentProgram).orElseThrow();
        require(flatLayout.invokeTargetOffset() == 24 &&
                flatLayout.methodInfoOffset() == 40 &&
                flatLayout.methodCodeOffset() == 64,
                "flattened delegate offsets differ");

        var fields = new StructureDataType(
                GhidraTypeImporter.ROOT, "System_Delegate_Fields", 72, manager);
        fields.setPackingEnabled(false);
        fields.replaceAtOffset(0, word, -1, "method_ptr", null);
        fields.replaceAtOffset(8, word, -1, "invoke_impl", null);
        fields.replaceAtOffset(16, word, -1, "m_target", null);
        fields.replaceAtOffset(24, word, -1, "method", null);
        fields.replaceAtOffset(32, word, -1, "delegate_trampoline", null);
        fields.replaceAtOffset(40, word, -1, "extra_arg", null);
        fields.replaceAtOffset(48, word, -1, "method_code", null);
        DataType storedFields = manager.addDataType(
                fields, DataTypeConflictHandler.REPLACE_HANDLER);

        addObjectType("System_Delegate_o", storedFields);
        addObjectType("System_Action_int__o", storedFields);
    }

    private void addObjectType(String name, DataType fields) {
        var manager = currentProgram.getDataTypeManager();
        var object = new StructureDataType(GhidraTypeImporter.ROOT, name, 88, manager);
        object.setPackingEnabled(false);
        object.replaceAtOffset(0, new PointerDataType(null, 8, manager),
                -1, "klass", null);
        object.replaceAtOffset(8, new PointerDataType(null, 8, manager),
                -1, "monitor", null);
        object.replaceAtOffset(16, fields, -1, "fields", null);
        manager.addDataType(object, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    private Function createFixtureFunction(Address entry, String label) {
        DisassembleCommand disassemble = new DisassembleCommand(entry, null, true);
        disassemble.enableCodeAnalysis(false);
        require(disassemble.applyTo(currentProgram, monitor),
                "could not disassemble " + label);
        if (currentProgram.getFunctionManager().getFunctionAt(entry) == null) {
            require(new CreateFunctionCmd(entry).applyTo(currentProgram, monitor),
                    "could not create " + label);
        }
        Function result = currentProgram.getFunctionManager().getFunctionAt(entry);
        require(result != null, label + " is missing");
        return result;
    }

    private void applySignatures(long blockOffset) throws Exception {
        var methods = List.of(
                new ScriptMethodReader.ScriptMethod(
                        Math.addExact(blockOffset, DELEGATE_CALLER),
                        "Fixture$$InvokeDelegate",
                        "void Fixture__InvokeDelegate (System_Action_int__o* callback);",
                        "vp", "Fixture"),
                new ScriptMethodReader.ScriptMethod(
                        Math.addExact(blockOffset, MISMATCH_CALLER),
                        "Fixture$$InvokeMismatchedDelegate",
                        "void Fixture__InvokeMismatchedDelegate " +
                        "(System_Action_int__o* first, System_Action_int__o* second);",
                        "vpp", "Fixture"),
                new ScriptMethodReader.ScriptMethod(
                        Math.addExact(blockOffset, TAIL_CALLER),
                        "Fixture$$TailInvokeDelegate",
                        "void Fixture__TailInvokeDelegate " +
                        "(System_Action_int__o* callback);",
                        "vp", "Fixture"));
        new GhidraMethodImporter(currentProgram, monitor).importMethods(methods);
    }

    private void verifyRawTailCall(Address callsite) {
        var instruction = currentProgram.getListing().getInstructionAt(callsite);
        require(instruction != null, "delegate tail-call instruction is missing");
        int indirectBranches = 0;
        int indirectCalls = 0;
        for (var operation : instruction.getPcode()) {
            if (operation.getOpcode() == PcodeOp.BRANCHIND) {
                indirectBranches++;
            }
            else if (operation.getOpcode() == PcodeOp.CALLIND) {
                indirectCalls++;
            }
        }
        require(indirectBranches == 1 && indirectCalls == 0,
                "delegate tail call is not raw BRANCHIND");
    }

    private void verifyPublishedOverride(Function function, Address callsite)
            throws Exception {
        FunctionSignature signature = overrideAt(function, callsite);
        require(signature != null, "delegate prototype override is missing");
        require(signature.getArguments().length == 3 &&
                signature.getArguments()[1].getDataType().getLength() == Integer.BYTES,
                "delegate prototype override differs");

        var decompiler = new DecompInterface();
        try {
            decompiler.toggleCCode(false);
            require(decompiler.openProgram(currentProgram),
                    "could not open delegate-call fixture");
            require(decompiler.setSimplificationStyle("normalize"),
                    "could not normalize delegate-call fixture");
            var result = decompiler.decompileFunction(function, 30, monitor);
            require(result.decompileCompleted() && result.getHighFunction() != null,
                    "could not decompile published delegate-call fixture");
            boolean indirect = false;
            var operations = result.getHighFunction().getPcodeOps();
            while (operations.hasNext()) {
                var operation = operations.next();
                if (operation.getSeqnum().getTarget().equals(callsite) &&
                        operation.getOpcode() == PcodeOp.CALLIND) {
                    indirect = true;
                }
            }
            require(indirect, "delegate prototype changed CALLIND to a direct call");
        }
        finally {
            decompiler.dispose();
        }
    }

    private FunctionSignature overrideAt(Function function, Address callsite) {
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

    private static void require(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }
}
