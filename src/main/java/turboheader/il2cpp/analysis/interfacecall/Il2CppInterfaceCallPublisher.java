package turboheader.il2cpp.analysis.interfacecall;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

public final class Il2CppInterfaceCallPublisher {
    private Il2CppInterfaceCallPublisher() {
    }

    public static PublicationStats publish(Program program,
            List<Il2CppInterfaceCallAnalyzer.ProvenCall> proofs, TaskMonitor taskMonitor)
            throws Exception {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(proofs, "proofs");
        TaskMonitor monitor = taskMonitor == null ? TaskMonitor.DUMMY : taskMonitor;
        long started = System.nanoTime();

        List<Publication> publications = validate(program, proofs, monitor);
        int retained = 0;
        int pending = 0;
        for (Publication publication : publications) {
            if (publication.existing()) {
                retained++;
            }
            else {
                pending++;
            }
        }
        if (pending == 0) {
            return new PublicationStats(publications.size(), 0, retained,
                    System.nanoTime() - started);
        }

        int transaction = program.startTransaction("Publish IL2CPP interface calls");
        boolean commit = false;
        try {
            for (Publication publication : publications) {
                monitor.checkCancelled();
                if (publication.existing()) {
                    continue;
                }
                Reference reference = program.getReferenceManager().addMemoryReference(
                        publication.callsite(), publication.target(),
                        RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS,
                        Reference.MNEMONIC);
                program.getReferenceManager().setPrimary(reference, true);
                if (!reference.isPrimary() ||
                        !reference.getToAddress().equals(publication.target())) {
                    throw new IllegalStateException(
                            "interface-call override was not activated at " +
                            publication.callsite());
                }
            }
            commit = true;
        }
        finally {
            program.endTransaction(transaction, commit);
        }
        return new PublicationStats(publications.size(), pending, retained,
                System.nanoTime() - started);
    }

    private static List<Publication> validate(Program program,
            List<Il2CppInterfaceCallAnalyzer.ProvenCall> proofs, TaskMonitor monitor)
            throws Exception {
        Map<Address, Address> targets = new LinkedHashMap<>();
        for (var proof : proofs) {
            monitor.checkCancelled();
            Address previous = targets.putIfAbsent(proof.callsite(), proof.target());
            if (previous != null && !previous.equals(proof.target())) {
                throw new IllegalStateException(
                        "conflicting interface-call proofs at " + proof.callsite());
            }
        }

        List<Publication> publications = new ArrayList<>();
        for (var entry : targets.entrySet()) {
            monitor.checkCancelled();
            publications.add(validate(program, entry.getKey(), entry.getValue()));
        }
        publications.sort(Comparator.comparing(Publication::callsite));
        return List.copyOf(publications);
    }

    private static Publication validate(Program program, Address callsite, Address target) {
        Instruction instruction = program.getListing().getInstructionAt(callsite);
        if (instruction == null) {
            throw new IllegalStateException(
                    "interface-call instruction is missing at " + callsite);
        }
        if (program.getFunctionManager().getFunctionAt(target) == null) {
            throw new IllegalStateException(
                    "interface-call target function is missing at " + target);
        }

        Reference active = null;
        for (Reference reference : instruction.getReferencesFrom()) {
            if (!reference.getReferenceType().equals(
                    RefType.CALL_OVERRIDE_UNCONDITIONAL)) {
                continue;
            }
            if (active != null || !reference.isPrimary() ||
                    !reference.getToAddress().equals(target)) {
                throw new IllegalStateException(
                        "conflicting call override at " + callsite);
            }
            active = reference;
        }
        if (active != null) {
            return new Publication(callsite, target, true);
        }

        int indirectCalls = 0;
        for (PcodeOp operation : instruction.getPcode()) {
            if (operation.getOpcode() == PcodeOp.CALLIND) {
                indirectCalls++;
            }
        }
        if (indirectCalls != 1) {
            throw new IllegalStateException(
                    "interface-call site does not contain one CALLIND at " + callsite);
        }
        return new Publication(callsite, target, false);
    }

    private record Publication(Address callsite, Address target, boolean existing) {
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
