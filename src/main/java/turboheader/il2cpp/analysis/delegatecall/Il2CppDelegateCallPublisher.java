package turboheader.il2cpp.analysis.delegatecall;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;

/** Publishes validated delegate prototypes without changing indirect targets. */
public final class Il2CppDelegateCallPublisher {
    private Il2CppDelegateCallPublisher() {
    }

    public static PublicationStats publish(Program program,
            List<Il2CppDelegateCallAnalyzer.ProvenCall> proofs,
            TaskMonitor taskMonitor) throws Exception {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(proofs, "proofs");
        TaskMonitor monitor = taskMonitor == null ? TaskMonitor.DUMMY : taskMonitor;
        long started = System.nanoTime();
        List<Il2CppDelegateCallAnalyzer.ProvenCall> unique = unique(proofs, monitor);
        if (unique.isEmpty()) {
            return new PublicationStats(0, 0, 0, System.nanoTime() - started);
        }

        int transaction = program.startTransaction("Publish IL2CPP delegate prototypes");
        boolean commit = false;
        int retained = 0;
        int added = 0;
        try {
            List<Publication> publications = new ArrayList<>(unique.size());
            for (var proof : unique) {
                monitor.checkCancelled();
                DelegateCallPrototype prototype = DelegateCallPrototype.parse(
                        proof.typeId(), proof.objectType(), proof.signature());
                FunctionSignature signature = GhidraDelegatePrototypeResolver.resolve(
                        program, prototype);
                publications.add(validate(program, proof.callsite(), signature));
            }

            for (Publication publication : publications) {
                if (publication.existing()) {
                    retained++;
                }
            }
            for (Publication publication : publications) {
                monitor.checkCancelled();
                if (publication.existing()) {
                    continue;
                }
                HighFunctionDBUtil.writeOverride(publication.caller(),
                        publication.callsite(), publication.signature());
                FunctionSignature stored = existingSignature(
                        program, publication.caller(), publication.callsite());
                if (stored == null || !equivalent(stored, publication.signature())) {
                    throw new IllegalStateException(
                            "delegate prototype override was not activated at " +
                            publication.callsite());
                }
                added++;
            }
            commit = true;
        }
        finally {
            program.endTransaction(transaction, commit);
        }
        return new PublicationStats(unique.size(), added, retained,
                System.nanoTime() - started);
    }

    private static List<Il2CppDelegateCallAnalyzer.ProvenCall> unique(
            List<Il2CppDelegateCallAnalyzer.ProvenCall> proofs,
            TaskMonitor monitor) throws Exception {
        Map<Address, Il2CppDelegateCallAnalyzer.ProvenCall> byCallsite =
                new LinkedHashMap<>();
        for (var proof : proofs) {
            monitor.checkCancelled();
            var previous = byCallsite.putIfAbsent(proof.callsite(), proof);
            if (previous != null && (!previous.objectType().equals(proof.objectType()) ||
                    previous.typeId() != proof.typeId() ||
                    !previous.signature().equals(proof.signature()))) {
                throw new IllegalStateException(
                        "conflicting delegate-call proofs at " + proof.callsite());
            }
        }
        List<Il2CppDelegateCallAnalyzer.ProvenCall> result =
                new ArrayList<>(byCallsite.values());
        result.sort(Comparator.comparing(
                Il2CppDelegateCallAnalyzer.ProvenCall::callsite));
        return List.copyOf(result);
    }

    private static Publication validate(Program program, Address callsite,
            FunctionSignature signature) {
        Function caller = program.getFunctionManager().getFunctionContaining(callsite);
        if (caller == null) {
            throw new IllegalStateException(
                    "delegate-call caller is missing at " + callsite);
        }
        Instruction instruction = program.getListing().getInstructionAt(callsite);
        if (instruction == null) {
            throw new IllegalStateException(
                    "delegate-call instruction is missing at " + callsite);
        }

        int indirectCalls = 0;
        int indirectBranches = 0;
        for (PcodeOp operation : instruction.getPcode()) {
            if (operation.getOpcode() == PcodeOp.CALLIND) {
                indirectCalls++;
            }
            else if (operation.getOpcode() == PcodeOp.BRANCHIND) {
                indirectBranches++;
            }
        }
        var flow = instruction.getFlowType();
        boolean indirectCall = indirectCalls == 1 && indirectBranches == 0;
        boolean indirectTailCall = indirectCalls == 0 && indirectBranches == 1 &&
                flow.isJump() && flow.isComputed() && !flow.hasFallthrough();
        if (!indirectCall && !indirectTailCall) {
            throw new IllegalStateException(
                    "delegate-call site is not one indirect call at " + callsite);
        }

        FunctionSignature existing = existingSignature(program, caller, callsite);
        if (existing != null) {
            if (!equivalent(existing, signature)) {
                throw new IllegalStateException(
                        "conflicting prototype override at " + callsite);
            }
            return new Publication(caller, callsite, signature, true);
        }

        return new Publication(caller, callsite, signature, false);
    }

    private static FunctionSignature existingSignature(Program program,
            Function caller, Address callsite) {
        var namespace = HighFunction.findOverrideSpace(caller);
        FunctionSignature result = null;
        for (Symbol symbol : program.getSymbolTable().getSymbols(callsite)) {
            if (symbol.getSymbolType() != SymbolType.LABEL ||
                    !symbol.getName().startsWith("prt")) {
                continue;
            }
            if (namespace == null ||
                    !symbol.getParentNamespace().equals(namespace)) {
                if (HighFunction.isOverrideNamespace(symbol.getParentNamespace())) {
                    throw new IllegalStateException(
                            "prototype override belongs to another function at " + callsite);
                }
                continue;
            }
            DataTypeSymbol stored = HighFunctionDBUtil.readOverride(symbol);
            if (stored == null || !(stored.getDataType() instanceof FunctionSignature signature) ||
                    result != null) {
                throw new IllegalStateException(
                        "invalid prototype override at " + callsite);
            }
            result = signature;
        }
        return result;
    }

    private static boolean equivalent(FunctionSignature first,
            FunctionSignature second) {
        if (!DataTypeUtilities.isSameOrEquivalentDataType(
                first.getReturnType(), second.getReturnType()) ||
                first.hasVarArgs() != second.hasVarArgs() ||
                first.hasNoReturn() != second.hasNoReturn() ||
                !Objects.equals(first.getCallingConventionName(),
                        second.getCallingConventionName())) {
            return false;
        }
        var firstArguments = first.getArguments();
        var secondArguments = second.getArguments();
        if (firstArguments.length != secondArguments.length) {
            return false;
        }
        for (int index = 0; index < firstArguments.length; index++) {
            if (!DataTypeUtilities.isSameOrEquivalentDataType(
                    firstArguments[index].getDataType(),
                    secondArguments[index].getDataType())) {
                return false;
            }
        }
        return true;
    }

    private record Publication(Function caller, Address callsite,
            FunctionSignature signature, boolean existing) {
    }

    public record PublicationStats(int requested, int added, int retained,
            long elapsedNanos) {
        public PublicationStats {
            if (requested < 0 || added < 0 || retained < 0 ||
                    added + retained != requested || elapsedNanos < 0) {
                throw new IllegalArgumentException("invalid publication statistics");
            }
        }

        public double elapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }
}
