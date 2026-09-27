// Verifies an exact AArch64 shared-generic physical call.
// @category Test

import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.SymbolType;
import turboheader.il2cpp.analysis.sharedgeneric.Il2CppSharedGenericCallAnalyzer;
import turboheader.il2cpp.analysis.sharedgeneric.Il2CppSharedGenericCallPublisher;
import turboheader.il2cpp.metadata.Il2CppSharedGenericCallStore;

public class VerifyTurboHeaderSharedGenericCall extends GhidraScript {
    private static final long CALLER = 0x540;
    private static final long CALLER_ONE_ARG = 0x5A0;
    private static final long CALLER_THREE_ARGS = 0x600;
    private static final long BODY = 0x560;
    private static final long METHOD_INFO = 0x580;
    private static final long METHOD_INFO_ONE_ARG = 0x5C0;
    private static final long METHOD_INFO_THREE_ARGS = 0x620;
    private static final long BOOL_CALLER = 0x640;
    private static final long BOOL_METHOD_INFO = 0x660;
    private static final long INT_CALLER = 0x680;
    private static final long INT_METHOD_INFO = 0x6A0;
    private static final long STRUCT_CALLER = 0x6C0;
    private static final long STRUCT_METHOD_INFO = 0x6E0;

    @Override
    protected void run() throws Exception {
        var block = currentProgram.getMemory().getBlock("interface_dispatch");
        require(block != null, "shared-generic fixture block is missing");
        block.setExecute(true);
        long blockOffset = block.getStart().subtract(currentProgram.getImageBase());
        Address callerEntry = currentProgram.getImageBase().add(
                Math.addExact(blockOffset, CALLER));
        Address bodyEntry = currentProgram.getImageBase().add(
                Math.addExact(blockOffset, BODY));
        Address methodInfo = currentProgram.getImageBase().add(
                Math.addExact(blockOffset, METHOD_INFO));
        Address oneArgEntry = currentProgram.getImageBase().add(
                Math.addExact(blockOffset, CALLER_ONE_ARG));
        Address oneArgMethodInfo = currentProgram.getImageBase().add(
                Math.addExact(blockOffset, METHOD_INFO_ONE_ARG));
        Address threeArgsEntry = currentProgram.getImageBase().add(
                Math.addExact(blockOffset, CALLER_THREE_ARGS));
        Address threeArgsMethodInfo = currentProgram.getImageBase().add(
                Math.addExact(blockOffset, METHOD_INFO_THREE_ARGS));
        Address boolEntry = currentProgram.getImageBase().add(
                Math.addExact(blockOffset, BOOL_CALLER));
        Address boolMethodInfo = currentProgram.getImageBase().add(
                Math.addExact(blockOffset, BOOL_METHOD_INFO));
        Address intEntry = currentProgram.getImageBase().add(
                Math.addExact(blockOffset, INT_CALLER));
        Address intMethodInfo = currentProgram.getImageBase().add(
                Math.addExact(blockOffset, INT_METHOD_INFO));
        Address structEntry = currentProgram.getImageBase().add(
                Math.addExact(blockOffset, STRUCT_CALLER));
        Address structMethodInfo = currentProgram.getImageBase().add(
                Math.addExact(blockOffset, STRUCT_METHOD_INFO));
        Function caller = createFixtureFunction(callerEntry, "shared-generic caller");
        Function oneArgCaller = createFixtureFunction(
                oneArgEntry, "one-argument shared-generic caller");
        Function threeArgsCaller = createFixtureFunction(
                threeArgsEntry, "three-argument shared-generic caller");
        Function boolCaller = createFixtureFunction(
                boolEntry, "Boolean shared-generic caller");
        Function intCaller = createFixtureFunction(
                intEntry, "integer shared-generic caller");
        Function structCaller = createFixtureFunction(
                structEntry, "structure shared-generic caller");
        createFixtureFunction(bodyEntry, "shared-generic body");

        var catalog = Il2CppSharedGenericCallStore.read(currentProgram).orElseThrow();
        long modificationNumber = currentProgram.getModificationNumber();
        var analysis = Il2CppSharedGenericCallAnalyzer.analyze(
                currentProgram, List.of(caller, oneArgCaller, threeArgsCaller,
                        boolCaller, intCaller, structCaller),
                catalog, monitor);
        require(analysis.outcome() == Il2CppSharedGenericCallAnalyzer.Outcome.COMPLETE,
                "shared-generic analysis did not complete");
        require(analysis.candidateFunctions() == 6 && analysis.candidateCalls() == 6 &&
                analysis.provenCalls() == 6 && analysis.rejections().isEmpty(),
                "shared-generic proof statistics differ: " + analysis);
        requireProof(analysis, callerEntry.add(0x10), bodyEntry, methodInfo);
        requireProof(analysis, oneArgEntry.add(0x0C), bodyEntry, oneArgMethodInfo);
        requireProof(analysis, threeArgsEntry.add(0x0C), bodyEntry,
                threeArgsMethodInfo);
        requireProof(analysis, boolEntry.add(0x0C), bodyEntry, boolMethodInfo);
        requireProof(analysis, intEntry.add(0x10), bodyEntry, intMethodInfo);
        requireProof(analysis, structEntry.add(0x0C), bodyEntry, structMethodInfo);
        require(currentProgram.getModificationNumber() == modificationNumber,
                "shared-generic analysis changed the program");

        var published = Il2CppSharedGenericCallPublisher.publish(
                currentProgram, analysis.proofs(), monitor);
        require(published.requested() == 6 && published.added() == 6 &&
                published.retained() == 0, "shared-generic publication differs");
        requireOverride(caller, callerEntry.add(0x10), 4);
        requireOverride(oneArgCaller, oneArgEntry.add(0x0C), 3);
        requireOverride(threeArgsCaller, threeArgsEntry.add(0x0C), 5);
        requireValueOverride(boolCaller, boolEntry.add(0x0C), 1, "bool");
        requireValueOverride(intCaller, intEntry.add(0x10), 2, "int32_t");
        requireValueOverride(structCaller, structEntry.add(0x0C), 3,
                "Fixture_Value_o");

        long beforeRepeat = currentProgram.getModificationNumber();
        var repeated = Il2CppSharedGenericCallPublisher.publish(
                currentProgram, analysis.proofs(), monitor);
        require(repeated.requested() == 6 && repeated.added() == 0 &&
                repeated.retained() == 6,
                "shared-generic publication is not idempotent");
        require(currentProgram.getModificationNumber() == beforeRepeat,
                "repeated shared-generic publication changed the program");
        println("TurboHeader shared-generic call proof verification passed");
        println("TurboHeader shared-generic override verification passed");
    }

    private void requireProof(Il2CppSharedGenericCallAnalyzer.AnalysisStats analysis,
            Address callsite, Address target, Address methodInfo) {
        for (var proof : analysis.proofs()) {
            if (proof.callsite().equals(callsite) && proof.target().equals(target) &&
                    proof.methodInfo().equals(methodInfo)) {
                return;
            }
        }
        throw new AssertionError("shared-generic proof is missing at " + callsite);
    }

    private void requireOverride(Function function, Address callsite, int arguments) {
        FunctionSignature signature = overrideAt(function, callsite);
        require(signature != null && signature.getArguments().length == arguments &&
                signature.getReturnType().getName().equals("void"),
                "shared-generic prototype override differs at " + callsite);
    }

    private void requireValueOverride(Function function, Address callsite,
            int resultIndex, String pointeeName) {
        FunctionSignature signature = overrideAt(function, callsite);
        require(signature != null && signature.getReturnType().getName().equals("void"),
                "value-result override is missing at " + callsite);
        var parameters = signature.getArguments();
        require(resultIndex >= 0 && resultIndex < parameters.length &&
                parameters[resultIndex].getDataType() instanceof Pointer pointer &&
                pointer.getDataType() != null &&
                pointer.getDataType().getName().equals(pointeeName),
                "value-result type differs at " + callsite);
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
                    "invalid shared-generic prototype override");
            require(result == null, "multiple shared-generic prototype overrides");
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
