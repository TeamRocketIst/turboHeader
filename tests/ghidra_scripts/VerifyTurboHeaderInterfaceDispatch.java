// @category Data Types

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import turboheader.il2cpp.Il2CppExportPlanner;
import turboheader.il2cpp.analysis.pipeline.Il2CppExportAnalysisService;
import turboheader.il2cpp.analysis.delegatecall.Il2CppDelegateCallAnalyzer;
import turboheader.il2cpp.analysis.helpers.Il2CppHelperKind;
import turboheader.il2cpp.analysis.interfacecall.Il2CppInterfaceCallAnalyzer;
import turboheader.il2cpp.analysis.interfacecall.Il2CppInterfaceCallPublisher;
import turboheader.il2cpp.decompile.Il2CppFunctionPreparationService;
import turboheader.il2cpp.exporting.Il2CppClassCatalog;
import turboheader.il2cpp.metadata.GhidraMethodImporter;
import turboheader.il2cpp.metadata.Il2CppDelegateSignatureCatalog;
import turboheader.il2cpp.metadata.Il2CppDelegateSignatureStore;
import turboheader.il2cpp.metadata.Il2CppInterfaceDispatchCatalog;
import turboheader.il2cpp.metadata.Il2CppInterfaceDispatchStore;
import turboheader.il2cpp.metadata.ScriptMethodReader;
import turboheader.il2cpp.project.Il2CppProgramFacts;

public class VerifyTurboHeaderInterfaceDispatch extends GhidraScript {
    private static final long HELPER = 0x100;
    private static final long OBJECT_NEW = 0x200;
    private static final long OBJECT_NEW_THUNK = 0x210;
    private static final long OBJECT_NEW_ANCHOR = 0x220;
    private static final long TARGET = 0x240;
    private static final long METHOD = 0x300;
    private static final long CANONICAL_CALLER = 0x400;
    private static final long FACTORY_CALLER = 0x440;
    private static final long RECEIVER_TYPE = 0x500;
    private static final long INTERFACE_TYPE = 0x508;
    private static final long RECEIVER_TYPE_GOT = 0x520;
    private static final long INTERFACE_TYPE_GOT = 0x528;

    @Override
    protected void run() throws Exception {
        require(currentProgram.getLanguage().getProcessor().toString().equalsIgnoreCase("AARCH64"),
                "interface-dispatch fixture requires AArch64");
        var block = currentProgram.getMemory().getBlock("interface_dispatch");
        require(block != null, "interface-dispatch fixture block is missing");
        block.setExecute(true);

        long blockOffset = block.getStart().subtract(currentProgram.getImageBase());
        long methodOffset = Math.addExact(blockOffset, METHOD);
        long helperOffset = Math.addExact(blockOffset, HELPER);
        long objectNewOffset = Math.addExact(blockOffset, OBJECT_NEW);
        long objectNewThunkOffset = Math.addExact(blockOffset, OBJECT_NEW_THUNK);
        long objectNewAnchorOffset = Math.addExact(blockOffset, OBJECT_NEW_ANCHOR);
        long targetOffset = Math.addExact(blockOffset, TARGET);
        long receiverTypeOffset = Math.addExact(blockOffset, RECEIVER_TYPE);
        long interfaceTypeOffset = Math.addExact(blockOffset, INTERFACE_TYPE);
        long receiverTypeGotOffset = Math.addExact(blockOffset, RECEIVER_TYPE_GOT);
        long interfaceTypeGotOffset = Math.addExact(blockOffset, INTERFACE_TYPE_GOT);
        Address entry = currentProgram.getImageBase().add(methodOffset);
        DisassembleCommand disassemble = new DisassembleCommand(entry, null, true);
        disassemble.enableCodeAnalysis(false);
        require(disassemble.applyTo(currentProgram, monitor), "could not disassemble managed fixture");
        CreateFunctionCmd create = new CreateFunctionCmd(entry);
        require(create.applyTo(currentProgram, monitor), "could not create managed fixture");
        Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
        require(function != null, "managed fixture function is missing");
        Function canonicalCaller = createFixtureFunction(
                currentProgram.getImageBase().add(
                        Math.addExact(blockOffset, CANONICAL_CALLER)),
                "canonical allocation caller");
        Function factoryCaller = createFixtureFunction(
                currentProgram.getImageBase().add(
                        Math.addExact(blockOffset, FACTORY_CALLER)),
                "factory-only caller");
        Address objectNewAddress = currentProgram.getImageBase().add(objectNewOffset);
        Address objectNewThunkAddress = currentProgram.getImageBase().add(objectNewThunkOffset);
        Address objectNewAnchor = currentProgram.getImageBase().add(objectNewAnchorOffset);
        createFixtureFunction(objectNewAddress, "allocation helper entry");
        createFixtureFunction(objectNewThunkAddress, "allocation helper thunk");
        createFixtureFunction(objectNewAnchor, "allocation helper anchor");
        Address receiverTypeAddress = currentProgram.getImageBase().add(receiverTypeOffset);
        Address interfaceTypeAddress = currentProgram.getImageBase().add(interfaceTypeOffset);
        Address receiverTypeGot = currentProgram.getImageBase().add(receiverTypeGotOffset);
        Address interfaceTypeGot = currentProgram.getImageBase().add(interfaceTypeGotOffset);
        configureTypeInfoData(block, receiverTypeAddress, receiverTypeGot,
                interfaceTypeAddress, interfaceTypeGot);

        String targetSignature =
                "void Sample__Run (Il2CppObject* self, MethodInfo* method);";
        var importedMethods = List.of(
                new ScriptMethodReader.ScriptMethod(objectNewOffset,
                        "il2cpp_object_new", "Il2CppObject* il2cpp_object_new " +
                        "(Il2CppClass* klass);", "pp", "Runtime"),
                new ScriptMethodReader.ScriptMethod(targetOffset,
                        "Sample$$Run", targetSignature, "vpp", "Sample"));
        new GhidraMethodImporter(currentProgram, monitor).importMethods(importedMethods);
        Function objectNew = currentProgram.getFunctionManager().getFunctionAt(objectNewAddress);
        Function objectNewThunk = currentProgram.getFunctionManager()
                .getFunctionAt(objectNewThunkAddress);
        Function objectNewBody = currentProgram.getFunctionManager()
                .getFunctionAt(objectNewAnchor);
        require(objectNew != null && objectNewThunk != null && objectNewBody != null,
                "allocation helper thunk chain is incomplete");
        objectNew.setThunkedFunction(objectNewThunk);
        objectNewThunk.setThunkedFunction(objectNewBody);
        require(objectNew.getThunkedFunction(true).equals(objectNewBody),
                "allocation helper thunk chain differs");

        var receiverType = new ScriptMethodReader.ScriptMetadata(
                receiverTypeOffset, "Sample_TypeInfo", "Sample_c*", 4);
        var interfaceType = new ScriptMethodReader.ScriptMetadata(
                interfaceTypeOffset, "IRunnable_TypeInfo", "IRunnable_c*", 2);
        var dispatch = new ScriptMethodReader.ScriptInterfaceDispatch(
                4, 2, 0, targetOffset, targetSignature);
        var delegateSignature = new ScriptMethodReader.ScriptDelegateSignature(
                7, "System_Action_int__o*",
                "void delegate_invoke (Il2CppMethodPointer methodCode, int32_t value, " +
                "const MethodInfo* method);");
        var script = new ScriptMethodReader.ScriptData(
                List.of(importedMethods.get(1)), List.of(receiverType, interfaceType),
                List.of(), List.of(), Optional.of(List.of(dispatch)),
                Optional.of(List.of(delegateSignature)));
        Il2CppInterfaceDispatchStore.replace(currentProgram,
                Il2CppInterfaceDispatchCatalog.fromScript(script));
        Il2CppDelegateSignatureStore.replace(currentProgram,
                Il2CppDelegateSignatureCatalog.fromScript(script));

        var prefilter = Il2CppInterfaceCallAnalyzer.analyze(
                currentProgram, List.of(function, canonicalCaller, factoryCaller),
                Map.of(
                        Il2CppHelperKind.INTERFACE_INVOKE_LOOKUP,
                        currentProgram.getImageBase().add(helperOffset),
                        Il2CppHelperKind.OBJECT_NEW, objectNewAnchor),
                monitor);
        require(prefilter.candidateFunctions() == 2 &&
                prefilter.prefilteredFunctions() == 1 &&
                prefilter.completedFunctions() == 2 && prefilter.failedFunctions() == 0,
                "interface-call prefilter statistics differ: " + prefilter);
        require(prefilter.provenCalls() == 1,
                "interface-call prefilter dropped the proven thunk caller");
        verifyWorkerParity(List.of(function, canonicalCaller, factoryCaller, function),
                Map.of(
                        Il2CppHelperKind.INTERFACE_INVOKE_LOOKUP,
                        currentProgram.getImageBase().add(helperOffset),
                        Il2CppHelperKind.OBJECT_NEW, objectNewAnchor),
                prefilter);
        println("TurboHeader interface-call prefilter verification passed");

        Il2CppProgramFacts.replaceManagedMethodOffsets(currentProgram,
                List.of(methodOffset, targetOffset), List.of());
        var ready = new Il2CppFunctionPreparationService.PreparedFunction(function, function);
        var classEntry = new Il2CppClassCatalog.ClassEntry(
                "Fixture.Dispatch", "Dispatch.cs", Path.of("fixtures", "Dispatch.cs"));
        var classPlan = new Il2CppExportPlanner.ClassPlan(
                classEntry, Path.of("Fixture", "Dispatch.cpp"), List.of(function));
        var preparedClass = new Il2CppFunctionPreparationService.PreparedClassPlan(
                classPlan, List.of(ready));
        var preparation = new Il2CppFunctionPreparationService.PreparationResult(
                List.of(preparedClass), List.of(ready), 1, 0, 0);

        var after = Il2CppExportAnalysisService.analyzeAfterPreparation(
                currentProgram, preparation, 8, monitor);
        require(after.delegatePrototypes().orElseThrow().size() == 1 &&
                after.delegatePrototypes().orElseThrow().forTypeId(7).isPresent(),
                "delegate prototype catalogue was not loaded during export analysis");
        require(after.delegateCalls().outcome() ==
                Il2CppDelegateCallAnalyzer.Outcome.MISSING_LAYOUT,
                "delegate analysis did not fail closed without imported delegate fields");
        require(after.publishedDelegateCalls().requested() == 0 &&
                after.publishedDelegateCalls().added() == 0 &&
                after.publishedDelegateCalls().retained() == 0,
                "missing delegate layout published a prototype override");
        var helpers = after.helpers();
        require(helpers.architectureCallsites() == 1 &&
                helpers.architectureCandidates() == 1 &&
                helpers.architectureProofs() == 1 && helpers.architectureRejected() == 0,
                "interface-dispatch proof counters differ");
        require(helpers.provenByKind().getOrDefault(
                Il2CppHelperKind.INTERFACE_INVOKE_LOOKUP, 0) == 1,
                "interface-dispatch helper was not published");
        require(helpers.provenByKind().getOrDefault(
                Il2CppHelperKind.OBJECT_NEW, 0) == 1,
                "object allocation helper was not published");
        require(helpers.anchors().get(Il2CppHelperKind.INTERFACE_INVOKE_LOOKUP).equals(
                currentProgram.getImageBase().add(helperOffset)),
                "interface-dispatch helper anchor differs");
        require(objectNewAnchor.equals(
                helpers.anchors().get(Il2CppHelperKind.OBJECT_NEW)),
                "object allocation helper anchor differs");

        Function helper = currentProgram.getFunctionManager().getFunctionAt(
                currentProgram.getImageBase().add(helperOffset));
        require(helper != null, "interface-dispatch helper function was not created");
        require(helper.getName().equals(
                "il2cpp_GetInterfaceInvokeDataFromVTableSlowPath_00001100"),
                "interface-dispatch helper name differs");
        require(helper.getParameterCount() == 3 &&
                helper.getReturnType().getName().contains("VirtualInvokeData"),
                "interface-dispatch helper signature differs");

        var calls = after.interfaceCalls();
        require(calls.outcome() == Il2CppInterfaceCallAnalyzer.Outcome.COMPLETE &&
                calls.candidateFunctions() == 1 && calls.completedFunctions() == 1 &&
                calls.prefilteredFunctions() == 0 && calls.failedFunctions() == 0,
                "interface-call candidate statistics differ");
        require(calls.helperCalls() == 1 && calls.associatedCalls() == 1 &&
                calls.provenCalls() == 1 && calls.conflictingCallsites() == 0,
                "interface-call proof statistics differ: " + calls);
        require(calls.functionTimings().size() == 1 &&
                calls.functionTimings().getFirst().completed() &&
                calls.functionTimings().getFirst().entry().equals(function.getEntryPoint()),
                "interface-call function timing differs");
        long measuredDecompilation = calls.functionTimings().stream()
                .mapToLong(Il2CppInterfaceCallAnalyzer.FunctionTiming::decompilationNanos)
                .sum();
        long measuredResolution = calls.functionTimings().stream()
                .mapToLong(Il2CppInterfaceCallAnalyzer.FunctionTiming::resolutionNanos)
                .sum();
        require(calls.timing().decompilationNanos() == measuredDecompilation &&
                calls.timing().resolutionNanos() == measuredResolution &&
                calls.timing().wallNanos() <= calls.elapsedNanos(),
                "interface-call phase timing differs");
        require(calls.rejections().total() == 0 &&
                calls.rejections().summary().equals("none") &&
                calls.rejectionSamples().isEmpty(),
                "proven interface call reported a rejection");
        var callProof = calls.proofs().getFirst();
        require(callProof.callsite().equals(entry.add(0x40)) &&
                callProof.target().equals(currentProgram.getImageBase().add(targetOffset)) &&
                callProof.receiverTypeId() == 4 && callProof.interfaceTypeId() == 2 &&
                callProof.interfaceSlot() == 0, "interface-call proof differs");
        require(after.publishedInterfaceCalls().requested() == 1 &&
                after.publishedInterfaceCalls().added() == 1 &&
                after.publishedInterfaceCalls().retained() == 0,
                "interface-call publication statistics differ");
        Address callsite = entry.add(0x40);
        Address unrelatedCallsite = entry.add(0x44);
        Address target = currentProgram.getImageBase().add(targetOffset);
        verifyOverride(function, callsite, unrelatedCallsite, target);

        long beforeRepeat = currentProgram.getModificationNumber();
        var repeated = Il2CppInterfaceCallPublisher.publish(
                currentProgram, calls.proofs(), monitor);
        require(repeated.requested() == 1 && repeated.added() == 0 &&
                repeated.retained() == 1,
                "interface-call publication is not idempotent");
        require(currentProgram.getModificationNumber() == beforeRepeat,
                "repeated interface-call publication changed the program");
        verifyConflictRejection(entry.add(0x44), entry.add(0x48), target,
                objectNewAnchor);
        println("TurboHeader interface-dispatch integration verification passed");
        println("TurboHeader interface-call P-code proof verification passed");
        println("TurboHeader interface-call override verification passed");
    }

    private void verifyWorkerParity(List<Function> functions,
            Map<Il2CppHelperKind, Address> anchors,
            Il2CppInterfaceCallAnalyzer.AnalysisStats expected) throws Exception {
        for (int workers : new int[] { 1, 2, 4, 8 }) {
            long before = currentProgram.getModificationNumber();
            var actual = Il2CppInterfaceCallAnalyzer.analyze(
                    currentProgram, functions, anchors, workers, monitor);
            require(currentProgram.getModificationNumber() == before,
                    "interface worker proof modified the program");
            require(actual.outcome() == expected.outcome() &&
                    actual.candidateFunctions() == expected.candidateFunctions() &&
                    actual.prefilteredFunctions() == expected.prefilteredFunctions() &&
                    actual.completedFunctions() == expected.completedFunctions() &&
                    actual.failedFunctions() == expected.failedFunctions() &&
                    actual.helperCalls() == expected.helperCalls() &&
                    actual.associatedCalls() == expected.associatedCalls() &&
                    actual.conflictingCallsites() == expected.conflictingCallsites() &&
                    actual.proofs().equals(expected.proofs()) &&
                    actual.rejections().equals(expected.rejections()) &&
                    actual.rejectionSamples().equals(expected.rejectionSamples()),
                    "interface worker proof differs for workers=" + workers);
            require(actual.timing().wallNanos() <= actual.elapsedNanos() &&
                    actual.functionTimings().size() == expected.functionTimings().size(),
                    "interface worker timing differs");
            for (int index = 0; index < actual.functionTimings().size(); index++) {
                var left = expected.functionTimings().get(index);
                var right = actual.functionTimings().get(index);
                require(left.entry().equals(right.entry()) &&
                        left.completed() == right.completed() &&
                        left.helperCalls() == right.helperCalls() &&
                        left.associatedCalls() == right.associatedCalls(),
                        "interface worker result order differs");
            }
        }
        long before = currentProgram.getModificationNumber();
        var missing = Il2CppInterfaceCallAnalyzer.analyze(
                currentProgram, functions, Map.of(), 8, monitor);
        require(missing.outcome() == Il2CppInterfaceCallAnalyzer.Outcome.MISSING_HELPERS &&
                missing.proofs().isEmpty() && currentProgram.getModificationNumber() == before,
                "missing helper analysis did not remain read-only and unresolved");
        var empty = Il2CppInterfaceCallAnalyzer.analyze(
                currentProgram, List.of(), anchors, 8, monitor);
        require(empty.outcome() == Il2CppInterfaceCallAnalyzer.Outcome.COMPLETE &&
                empty.candidateFunctions() == 0 && empty.proofs().isEmpty() &&
                empty.timing().proofWallNanos() == 0 &&
                currentProgram.getModificationNumber() == before,
                "empty interface analysis opened workers or changed the program");
        println("TurboHeader interface worker parity verification passed");
    }

    private Function createFixtureFunction(Address address, String description) {
        DisassembleCommand disassemble = new DisassembleCommand(address, null, true);
        disassemble.enableCodeAnalysis(false);
        require(disassemble.applyTo(currentProgram, monitor),
                "could not disassemble " + description);
        if (currentProgram.getFunctionManager().getFunctionAt(address) == null) {
            require(new CreateFunctionCmd(address).applyTo(currentProgram, monitor),
                    "could not create " + description);
        }
        Function function = currentProgram.getFunctionManager().getFunctionAt(address);
        require(function != null, description + " function is missing");
        return function;
    }

    private void configureTypeInfoData(MemoryBlock codeBlock,
            Address receiverType, Address receiverGot,
            Address interfaceType, Address interfaceGot) throws Exception {
        currentProgram.getMemory().split(codeBlock, receiverType);
        MemoryBlock dataBlock = currentProgram.getMemory().getBlock(receiverType);
        dataBlock.setRead(true);
        dataBlock.setWrite(false);
        dataBlock.setExecute(false);

        var pointer = new PointerDataType(null, currentProgram.getDefaultPointerSize(),
                currentProgram.getDataTypeManager());
        Data receiverData = createData(receiverGot, pointer);
        Data interfaceData = createData(interfaceGot, pointer);
        require(receiverData != null && receiverData.isPointer() &&
                receiverType.equals(receiverData.getValue()),
                "receiver TypeInfo GOT pointer differs");
        require(interfaceData != null && interfaceData.isPointer() &&
                interfaceType.equals(interfaceData.getValue()),
                "interface TypeInfo GOT pointer differs");
        require(receiverData.getValueReferences().length == 1 &&
                interfaceData.getValueReferences().length == 1,
                "TypeInfo GOT reference count differs");
    }

    private void verifyConflictRejection(Address conflictingCallsite,
            Address untouchedCallsite, Address target, Address conflictingTarget)
            throws Exception {
        Reference conflicting = currentProgram.getReferenceManager().addMemoryReference(
                conflictingCallsite, conflictingTarget,
                RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS,
                Reference.MNEMONIC);
        currentProgram.getReferenceManager().setPrimary(conflicting, true);

        var first = new Il2CppInterfaceCallAnalyzer.ProvenCall(
                untouchedCallsite, target, 4, 2, 0);
        var second = new Il2CppInterfaceCallAnalyzer.ProvenCall(
                conflictingCallsite, target, 4, 2, 0);
        boolean rejected = false;
        try {
            Il2CppInterfaceCallPublisher.publish(
                    currentProgram, List.of(first, second), monitor);
        }
        catch (IllegalStateException expected) {
            rejected = true;
        }
        require(rejected, "conflicting interface-call override was accepted");
        for (var reference : currentProgram.getListing()
                .getInstructionAt(untouchedCallsite).getReferencesFrom()) {
            require(!reference.getReferenceType().equals(
                    RefType.CALL_OVERRIDE_UNCONDITIONAL),
                    "conflicting publication partially changed the program");
        }
    }

    private void verifyOverride(Function function, Address callsite,
            Address unrelatedCallsite, Address target) throws Exception {
        int intendedOverrides = 0;
        for (var reference : currentProgram.getListing()
                .getInstructionAt(callsite).getReferencesFrom()) {
            if (reference.getReferenceType().equals(
                    RefType.CALL_OVERRIDE_UNCONDITIONAL)) {
                require(reference.isPrimary() && reference.getToAddress().equals(target),
                        "interface-call override differs");
                intendedOverrides++;
            }
        }
        require(intendedOverrides == 1, "interface-call override count differs");
        for (var reference : currentProgram.getListing()
                .getInstructionAt(unrelatedCallsite).getReferencesFrom()) {
            require(!reference.getReferenceType().equals(
                    RefType.CALL_OVERRIDE_UNCONDITIONAL),
                    "unrelated indirect call received an override");
        }

        var decompiler = new DecompInterface();
        try {
            decompiler.toggleCCode(false);
            require(decompiler.openProgram(currentProgram),
                    "could not open published interface-call fixture");
            var result = decompiler.decompileFunction(function, 30, monitor);
            require(result.decompileCompleted() && result.getHighFunction() != null,
                    "could not decompile published interface-call fixture");
            boolean direct = false;
            boolean unrelatedIndirect = false;
            var operations = result.getHighFunction().getPcodeOps();
            while (operations.hasNext()) {
                var operation = operations.next();
                Address address = operation.getSeqnum().getTarget();
                if (address.equals(callsite) && operation.getOpcode() == PcodeOp.CALL &&
                        operation.getInput(0).getAddress().equals(target)) {
                    direct = true;
                }
                if (address.equals(unrelatedCallsite) &&
                        operation.getOpcode() == PcodeOp.CALLIND) {
                    unrelatedIndirect = true;
                }
            }
            require(direct, "published interface call did not become a direct CALL");
            require(unrelatedIndirect, "unrelated indirect call did not remain CALLIND");
        }
        finally {
            decompiler.dispose();
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
