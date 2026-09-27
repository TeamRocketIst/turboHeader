package turboheader.il2cpp.analysis.sharedgeneric;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.ContextEvaluatorAdapter;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.task.TaskMonitor;
import turboheader.il2cpp.metadata.Il2CppSharedGenericCallCatalog;
import turboheader.il2cpp.metadata.SharedGenericCallSignature;

public final class Il2CppSharedGenericCallAnalyzer {
    private static final int MAX_BACKWARD_INSTRUCTIONS = 24;
    private static final int MAX_REJECTION_SAMPLES = 8;

    private Il2CppSharedGenericCallAnalyzer() {
    }

    public static AnalysisStats analyze(Program program, List<Function> functions,
            Il2CppSharedGenericCallCatalog catalog, TaskMonitor taskMonitor)
            throws Exception {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(functions, "functions");
        Objects.requireNonNull(catalog, "catalog");
        TaskMonitor monitor = taskMonitor == null ? TaskMonitor.DUMMY : taskMonitor;
        long started = System.nanoTime();

        String processor = program.getLanguage().getProcessor().toString();
        if (!processor.equalsIgnoreCase("AARCH64")) {
            return AnalysisStats.unsupported(processor, System.nanoTime() - started);
        }

        Map<Address, List<MappedEntry>> byTarget = mappedEntries(program, catalog);
        List<FunctionCandidates> candidateFunctions = selectCandidates(
                program, functions, byTarget, monitor);
        Register stackPointer = requireRegister(program, "sp");
        List<ProvenCall> proofs = new ArrayList<>();
        Map<RejectionReason, Integer> rejectionCounts = new LinkedHashMap<>();
        List<RejectionSample> rejectionSamples = new ArrayList<>();
        int candidates = 0;

        for (FunctionCandidates group : candidateFunctions) {
            monitor.checkCancelled();
            candidates += group.calls().size();
            SymbolicPropogator propagation = propagate(program, group.function(), monitor);
            for (Candidate candidate : group.calls()) {
                monitor.checkCancelled();
                ProofResult result = prove(program, group.function(), candidate,
                        propagation, stackPointer);
                if (result.proof() != null) {
                    proofs.add(result.proof());
                    continue;
                }
                rejectionCounts.merge(result.rejection(), 1, Integer::sum);
                if (rejectionSamples.size() < MAX_REJECTION_SAMPLES) {
                    rejectionSamples.add(new RejectionSample(
                            candidate.instruction().getAddress(), result.rejection()));
                }
            }
        }

        proofs.sort(Comparator.comparing(ProvenCall::callsite));
        return new AnalysisStats(Outcome.COMPLETE, processor, functions.size(),
                candidateFunctions.size(), candidates, proofs.size(), List.copyOf(proofs),
                Map.copyOf(rejectionCounts), List.copyOf(rejectionSamples),
                System.nanoTime() - started);
    }

    private static Map<Address, List<MappedEntry>> mappedEntries(Program program,
            Il2CppSharedGenericCallCatalog catalog) throws Exception {
        Map<Address, List<MappedEntry>> result = new LinkedHashMap<>();
        Map<String, Optional<GhidraSharedGenericPrototypeResolver.CallStorage>> storageCache =
                new LinkedHashMap<>();
        Address imageBase = program.getImageBase();
        for (var entry : catalog.entries()) {
            Address methodInfo = imageBase.addNoWrap(entry.methodInfoAddress());
            Address method = imageBase.addNoWrap(entry.methodAddress());
            var prototype = SharedGenericCallSignature.parse(entry.signature());
            var storage = storageCache.computeIfAbsent(entry.signature(), ignored ->
                    GhidraSharedGenericPrototypeResolver.resolveStorage(program, prototype));
            result.computeIfAbsent(method, ignored -> new ArrayList<>())
                    .add(new MappedEntry(entry, methodInfo, method,
                            storage.orElse(null)));
        }
        return result;
    }

    private static List<FunctionCandidates> selectCandidates(Program program,
            List<Function> functions, Map<Address, List<MappedEntry>> byTarget,
            TaskMonitor monitor) throws Exception {
        List<FunctionCandidates> result = new ArrayList<>();
        for (Function function : functions) {
            monitor.checkCancelled();
            List<Candidate> calls = new ArrayList<>();
            var instructions = program.getListing().getInstructions(function.getBody(), true);
            while (instructions.hasNext()) {
                monitor.checkCancelled();
                Instruction instruction = instructions.next();
                Address target = directCallTarget(instruction);
                List<MappedEntry> entries = target == null ? null : byTarget.get(target);
                if (entries != null) {
                    calls.add(new Candidate(instruction, target, entries));
                }
            }
            if (!calls.isEmpty()) {
                result.add(new FunctionCandidates(function, List.copyOf(calls)));
            }
        }
        return List.copyOf(result);
    }

    private static ProofResult prove(Program program, Function function,
            Candidate candidate, SymbolicPropogator propagation,
            Register stackPointer) {
        List<Register> methodInfoRegisters = methodInfoRegisters(candidate.entries());
        if (methodInfoRegisters.isEmpty()) {
            return ProofResult.rejected(RejectionReason.ABI_STORAGE);
        }

        boolean foundLoad = false;
        boolean resolvedValue = false;
        List<EntryMatch> matches = new ArrayList<>();
        for (Register register : methodInfoRegisters) {
            LoadSource methodInfoLoad = findMethodInfoLoad(program, function,
                    candidate.instruction(), register);
            if (methodInfoLoad == null) {
                continue;
            }
            foundLoad = true;
            SymbolicPropogator.Value methodInfoValue = propagation.getRegisterValue(
                    methodInfoLoad.instruction().getAddress(), methodInfoLoad.baseRegister());
            if (methodInfoValue == null || methodInfoValue.isRegisterRelativeValue()) {
                continue;
            }
            resolvedValue = true;
            for (MappedEntry entry : candidate.entries()) {
                if (entry.storage() == null ||
                        !sameBaseRegister(entry.storage().methodInfo(), register) ||
                        entry.methodInfo().getOffset() != methodInfoValue.getValue()) {
                    continue;
                }
                matches.add(new EntryMatch(entry, methodInfoValue.getValue()));
            }
        }
        if (matches.isEmpty()) {
            if (!foundLoad) {
                return ProofResult.rejected(RejectionReason.METHOD_INFO_LOAD);
            }
            if (!resolvedValue) {
                return ProofResult.rejected(RejectionReason.METHOD_INFO_VALUE);
            }
            return ProofResult.rejected(RejectionReason.METHOD_INFO_MISMATCH);
        }
        if (matches.size() != 1) {
            return ProofResult.rejected(RejectionReason.METHOD_INFO_AMBIGUOUS);
        }
        EntryMatch match = matches.getFirst();
        MappedEntry matched = match.entry();

        SymbolicPropogator.Value resultValue = propagation.getRegisterValue(
                candidate.instruction().getAddress(), matched.storage().result());
        boolean stackRelative = resultValue != null &&
                resultValue.isRegisterRelativeValue() &&
                sameBaseRegister(resultValue.getRelativeRegister(), stackPointer);
        long resultOffset = stackRelative ? resultValue.getValue() : 0;
        boolean accepted = SharedGenericCallProof.accepts(
                candidate.target().getOffset(), matched.method().getOffset(),
                match.methodInfoValue(), matched.methodInfo().getOffset(),
                stackRelative, resultOffset, program.getDefaultPointerSize());
        if (!accepted) {
            return ProofResult.rejected(RejectionReason.RESULT_BUFFER);
        }
        return ProofResult.proven(new ProvenCall(candidate.instruction().getAddress(),
                matched.method(), matched.methodInfo(), matched.entry().methodAddress(),
                matched.entry().methodInfoAddress(), matched.entry().signature()));
    }

    private static List<Register> methodInfoRegisters(List<MappedEntry> entries) {
        List<Register> result = new ArrayList<>();
        for (MappedEntry entry : entries) {
            if (entry.storage() == null) {
                continue;
            }
            Register register = entry.storage().methodInfo().getBaseRegister();
            boolean found = false;
            for (Register existing : result) {
                if (sameBaseRegister(existing, register)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                result.add(register);
            }
        }
        return List.copyOf(result);
    }

    private static SymbolicPropogator propagate(Program program, Function function,
            TaskMonitor monitor) throws Exception {
        SymbolicPropogator propagation = new SymbolicPropogator(program, true);
        propagation.setParamRefCheck(false);
        propagation.setParamPointerRefCheck(false);
        propagation.setReturnRefCheck(false);
        propagation.setStoredRefCheck(false);
        propagation.flowConstants(function.getEntryPoint(), function.getBody(),
                new ContextEvaluatorAdapter(), false, monitor);
        return propagation;
    }

    private static LoadSource findMethodInfoLoad(Program program, Function function,
            Instruction call, Register destination) {
        Instruction current = call;
        for (int count = 0; count < MAX_BACKWARD_INSTRUCTIONS; count++) {
            Instruction previous = program.getListing().getInstructionBefore(
                    current.getAddress());
            if (previous == null || !function.getBody().contains(previous.getAddress()) ||
                    previous.getFallThrough() == null ||
                    !previous.getFallThrough().equals(current.getAddress())) {
                return null;
            }
            if (writesRegister(program, previous, destination)) {
                Register base = exactLoadBase(program, previous, destination);
                return base == null ? null : new LoadSource(previous, base);
            }
            current = previous;
        }
        return null;
    }

    private static boolean writesRegister(Program program, Instruction instruction,
            Register destination) {
        for (PcodeOp operation : instruction.getPcode()) {
            if (sameRegister(program, operation.getOutput(), destination)) {
                return true;
            }
        }
        return false;
    }

    private static Register exactLoadBase(Program program, Instruction instruction,
            Register destination) {
        PcodeOp[] operations = instruction.getPcode();
        for (int index = 0; index < operations.length; index++) {
            PcodeOp operation = operations[index];
            if (operation.getOpcode() != PcodeOp.LOAD ||
                    !sameRegister(program, operation.getOutput(), destination)) {
                continue;
            }
            Varnode address = operation.getInput(1);
            Register direct = registerFor(program, address);
            if (direct != null) {
                return direct;
            }
            for (int definition = index - 1; definition >= 0; definition--) {
                PcodeOp source = operations[definition];
                if (!address.equals(source.getOutput())) {
                    continue;
                }
                if (source.getOpcode() != PcodeOp.COPY) {
                    return null;
                }
                return registerFor(program, source.getInput(0));
            }
        }
        return null;
    }

    private static Address directCallTarget(Instruction instruction) {
        Address target = null;
        int calls = 0;
        for (PcodeOp operation : instruction.getPcode()) {
            if (operation.getOpcode() == PcodeOp.CALLIND) {
                return null;
            }
            if (operation.getOpcode() != PcodeOp.CALL) {
                continue;
            }
            calls++;
            target = operation.getInput(0).getAddress();
        }
        return calls == 1 ? target : null;
    }

    private static Register requireRegister(Program program, String name) {
        Register register = program.getLanguage().getRegister(name);
        if (register == null) {
            throw new IllegalStateException("missing AArch64 register " + name);
        }
        return register;
    }

    private static Register registerFor(Program program, Varnode value) {
        if (value == null || !value.isRegister()) {
            return null;
        }
        return program.getLanguage().getRegister(value.getAddress(), value.getSize());
    }

    private static boolean sameRegister(Program program, Varnode value,
            Register expected) {
        Register actual = registerFor(program, value);
        return actual != null && actual.equals(expected);
    }

    private static boolean sameBaseRegister(Register first, Register second) {
        return first != null && second != null &&
                first.getBaseRegister().equals(second.getBaseRegister());
    }

    public enum Outcome {
        NOT_SUPPLIED,
        COMPLETE,
        UNSUPPORTED
    }

    public enum RejectionReason {
        ABI_STORAGE("physical parameter storage is unsupported"),
        METHOD_INFO_LOAD("no exact assigned-register metadata load"),
        METHOD_INFO_VALUE("metadata base is unresolved"),
        METHOD_INFO_MISMATCH("metadata slot is not in the catalogue"),
        METHOD_INFO_AMBIGUOUS("metadata slot is ambiguous"),
        RESULT_BUFFER("assigned result register is not a bounded stack buffer");

        private final String label;

        RejectionReason(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    public record ProvenCall(Address callsite, Address target, Address methodInfo,
            long methodAddress, long methodInfoAddress, String signature) {
    }

    public record RejectionSample(Address callsite, RejectionReason reason) {
    }

    public record AnalysisStats(Outcome outcome, String processor, int scannedFunctions,
            int candidateFunctions, int candidateCalls, int provenCalls,
            List<ProvenCall> proofs, Map<RejectionReason, Integer> rejections,
            List<RejectionSample> rejectionSamples, long elapsedNanos) {
        public AnalysisStats {
            Objects.requireNonNull(outcome, "outcome");
            Objects.requireNonNull(processor, "processor");
            proofs = List.copyOf(proofs);
            rejections = Map.copyOf(rejections);
            rejectionSamples = List.copyOf(rejectionSamples);
            if (scannedFunctions < 0 || candidateFunctions < 0 || candidateCalls < 0 ||
                    provenCalls < 0 || provenCalls != proofs.size() || elapsedNanos < 0) {
                throw new IllegalArgumentException("invalid shared-generic statistics");
            }
        }

        static AnalysisStats unsupported(String processor, long elapsedNanos) {
            return new AnalysisStats(Outcome.UNSUPPORTED, processor, 0, 0, 0, 0,
                    List.of(), Map.of(), List.of(), elapsedNanos);
        }

        public static AnalysisStats notSupplied(String processor) {
            return new AnalysisStats(Outcome.NOT_SUPPLIED, processor, 0, 0, 0, 0,
                    List.of(), Map.of(), List.of(), 0);
        }

        public double elapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }

    private record MappedEntry(Il2CppSharedGenericCallCatalog.Entry entry,
            Address methodInfo, Address method,
            GhidraSharedGenericPrototypeResolver.CallStorage storage) {
    }

    private record EntryMatch(MappedEntry entry, long methodInfoValue) {
    }

    private record Candidate(Instruction instruction, Address target,
            List<MappedEntry> entries) {
    }

    private record FunctionCandidates(Function function, List<Candidate> calls) {
    }

    private record LoadSource(Instruction instruction, Register baseRegister) {
    }

    private record ProofResult(ProvenCall proof, RejectionReason rejection) {
        static ProofResult proven(ProvenCall proof) {
            return new ProofResult(proof, null);
        }

        static ProofResult rejected(RejectionReason reason) {
            return new ProofResult(null, reason);
        }
    }
}
