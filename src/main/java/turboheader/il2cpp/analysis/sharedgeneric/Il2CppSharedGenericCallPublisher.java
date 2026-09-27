package turboheader.il2cpp.analysis.sharedgeneric;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.address.Address;
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
import turboheader.il2cpp.metadata.SharedGenericCallSignature;

public final class Il2CppSharedGenericCallPublisher {
    private Il2CppSharedGenericCallPublisher() {
    }

    public static PublicationStats publish(Program program,
            List<Il2CppSharedGenericCallAnalyzer.ProvenCall> proofs,
            TaskMonitor taskMonitor) throws Exception {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(proofs, "proofs");
        TaskMonitor monitor = taskMonitor == null ? TaskMonitor.DUMMY : taskMonitor;
        long started = System.nanoTime();
        List<Il2CppSharedGenericCallAnalyzer.ProvenCall> unique = unique(proofs, monitor);
        if (unique.isEmpty()) {
            return new PublicationStats(0, 0, 0, System.nanoTime() - started);
        }

        int transaction = program.startTransaction(
                "Publish IL2CPP shared generic prototypes");
        boolean commit = false;
        int retained = 0;
        int added = 0;
        try {
            List<Publication> publications = new ArrayList<>(unique.size());
            for (var proof : unique) {
                monitor.checkCancelled();
                var prototype = SharedGenericCallSignature.parse(proof.signature());
                FunctionSignature signature = GhidraSharedGenericPrototypeResolver.resolve(
                        program, proof.methodInfoAddress(), prototype);
                publications.add(validate(program, proof, signature));
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
                            "shared-generic prototype override was not activated at " +
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

    private static List<Il2CppSharedGenericCallAnalyzer.ProvenCall> unique(
            List<Il2CppSharedGenericCallAnalyzer.ProvenCall> proofs,
            TaskMonitor monitor) throws Exception {
        Map<Address, Il2CppSharedGenericCallAnalyzer.ProvenCall> byCallsite =
                new LinkedHashMap<>();
        for (var proof : proofs) {
            monitor.checkCancelled();
            var previous = byCallsite.putIfAbsent(proof.callsite(), proof);
            if (previous != null && (!previous.target().equals(proof.target()) ||
                    previous.methodInfoAddress() != proof.methodInfoAddress() ||
                    !previous.signature().equals(proof.signature()))) {
                throw new IllegalStateException(
                        "conflicting shared-generic proofs at " + proof.callsite());
            }
        }
        List<Il2CppSharedGenericCallAnalyzer.ProvenCall> result =
                new ArrayList<>(byCallsite.values());
        result.sort(Comparator.comparing(
                Il2CppSharedGenericCallAnalyzer.ProvenCall::callsite));
        return List.copyOf(result);
    }

    private static Publication validate(Program program,
            Il2CppSharedGenericCallAnalyzer.ProvenCall proof,
            FunctionSignature signature) {
        Function caller = program.getFunctionManager()
                .getFunctionContaining(proof.callsite());
        if (caller == null) {
            throw new IllegalStateException(
                    "shared-generic caller is missing at " + proof.callsite());
        }
        Instruction instruction = program.getListing().getInstructionAt(proof.callsite());
        if (instruction == null || !proof.target().equals(directCallTarget(instruction))) {
            throw new IllegalStateException(
                    "shared-generic site is not the proven direct call at " +
                    proof.callsite());
        }

        FunctionSignature existing = existingSignature(program, caller, proof.callsite());
        if (existing != null) {
            if (!equivalent(existing, signature)) {
                throw new IllegalStateException(
                        "conflicting prototype override at " + proof.callsite());
            }
            return new Publication(caller, proof.callsite(), signature, true);
        }
        return new Publication(caller, proof.callsite(), signature, false);
    }

    private static Address directCallTarget(Instruction instruction) {
        Address target = null;
        int calls = 0;
        for (PcodeOp operation : instruction.getPcode()) {
            if (operation.getOpcode() == PcodeOp.CALLIND) {
                return null;
            }
            if (operation.getOpcode() == PcodeOp.CALL) {
                calls++;
                target = operation.getInput(0).getAddress();
            }
        }
        return calls == 1 ? target : null;
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
            if (namespace == null || !symbol.getParentNamespace().equals(namespace)) {
                if (HighFunction.isOverrideNamespace(symbol.getParentNamespace())) {
                    throw new IllegalStateException(
                            "prototype override belongs to another function at " + callsite);
                }
                continue;
            }
            DataTypeSymbol stored = HighFunctionDBUtil.readOverride(symbol);
            if (stored == null ||
                    !(stored.getDataType() instanceof FunctionSignature signature) ||
                    result != null) {
                throw new IllegalStateException("invalid prototype override at " + callsite);
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
