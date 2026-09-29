package turboheader.il2cpp.analysis.delegatecall;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/** Read-only delegate-call proof over typed P-code. */
public final class Il2CppDelegateCallAnalyzer {
    private static final int MAX_REJECTION_SAMPLES = 4;

    private Il2CppDelegateCallAnalyzer() {
    }

    public static AnalysisStats analyze(Program program, List<Function> selectedFunctions,
            Optional<Il2CppDelegatePrototypeCatalog> prototypes,
            TaskMonitor taskMonitor) throws Exception {
        return analyze(program, selectedFunctions, prototypes, 1, taskMonitor);
    }

    public static AnalysisStats analyze(Program program, List<Function> selectedFunctions,
            Optional<Il2CppDelegatePrototypeCatalog> prototypes, int workers,
            TaskMonitor taskMonitor) throws Exception {
        DelegateProofCoordinator.validateWorkers(workers);
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(selectedFunctions, "selectedFunctions");
        Objects.requireNonNull(prototypes, "prototypes");
        TaskMonitor monitor = taskMonitor == null ? TaskMonitor.DUMMY : taskMonitor;
        monitor.checkCancelled();
        long started = System.nanoTime();
        if (prototypes.isEmpty()) {
            return empty(Outcome.DISABLED, started);
        }

        long layoutStarted = System.nanoTime();
        Optional<Il2CppDelegateFieldLayout> layout =
                Il2CppDelegateFieldLayout.read(program);
        long layoutNanos = System.nanoTime() - layoutStarted;
        if (layout.isEmpty()) {
            return empty(Outcome.MISSING_LAYOUT, started, layoutNanos);
        }

        long candidateStarted = System.nanoTime();
        List<Function> candidates = candidates(program, selectedFunctions, monitor);
        long candidateNanos = System.nanoTime() - candidateStarted;
        if (candidates.isEmpty()) {
            return new AnalysisStats(Outcome.COMPLETE, 0, 0, 0, 0, 0, 0, 0,
                    DelegateCallRejectionCounts.none(), List.of(), List.of(),
                    new PhaseTiming(layoutNanos, candidateNanos, 0, 0, 0),
                    System.nanoTime() - started);
        }

        long modificationNumber = program.getModificationNumber();
        long proofStarted = System.nanoTime();
        var results = DelegateProofCoordinator.analyze(candidates, workers, monitor,
                lane -> new DelegateProofWorker(program,
                        layout.orElseThrow(), prototypes.orElseThrow()));
        long proofWallNanos = System.nanoTime() - proofStarted;
        int completed = 0;
        int failed = 0;
        int indirectCalls = 0;
        int delegateCandidates = 0;
        int shapeRejected = 0;
        long decompilationNanos = 0;
        long resolutionNanos = 0;
        List<DelegateCallRejectionCounts.Reason> rejectionReasons = new ArrayList<>();
        List<RejectedCall> rejectionSamples = new ArrayList<>();
        List<ProvenCall> proofs = new ArrayList<>();

        for (int index = 0; index < candidates.size(); index++) {
            monitor.checkCancelled();
            Function function = candidates.get(index);
            var result = results.get(index);
            decompilationNanos = Math.addExact(decompilationNanos, result.decompilationNanos());
            resolutionNanos = Math.addExact(resolutionNanos, result.resolutionNanos());
            var resolved = result.resolved();
            if (resolved == null) {
                failed++;
                continue;
            }
            completed++;
            indirectCalls += resolved.indirectCalls();
            delegateCandidates += resolved.delegateCandidates();
            shapeRejected += resolved.shapeRejected();
            for (var call : resolved.calls()) {
                Address callsite = call.callAddress();
                if (!ownedCallsite(program, function, callsite)) {
                    var reason = DelegateCallRejectionCounts.Reason.CALLSITE;
                    rejectionReasons.add(reason);
                    if (rejectionSamples.size() < MAX_REJECTION_SAMPLES) {
                        rejectionSamples.add(new RejectedCall(callsite, reason));
                    }
                    continue;
                }
                if (call.resolution().proof().isPresent()) {
                    var proof = call.resolution().proof().orElseThrow();
                    proofs.add(new ProvenCall(callsite, proof.typeId(),
                            proof.objectType(), proof.signature()));
                    continue;
                }
                var reason = DelegateCallRejectionCounts.reason(call.resolution().status());
                rejectionReasons.add(reason);
                if (rejectionSamples.size() < MAX_REJECTION_SAMPLES) {
                    rejectionSamples.add(new RejectedCall(callsite, reason));
                }
            }
        }

        monitor.checkCancelled();
        if (program.getModificationNumber() != modificationNumber) {
            throw new IllegalStateException("delegate-call proof changed the Ghidra program");
        }
        proofs.sort(Comparator.comparing(ProvenCall::callsite));
        return new AnalysisStats(Outcome.COMPLETE, candidates.size(), completed, failed,
                indirectCalls, delegateCandidates, shapeRejected, proofs.size(),
                DelegateCallRejectionCounts.count(rejectionReasons), rejectionSamples, proofs,
                new PhaseTiming(layoutNanos, candidateNanos,
                        decompilationNanos, resolutionNanos, proofWallNanos),
                System.nanoTime() - started);
    }

    private static List<Function> candidates(Program program,
            List<Function> selectedFunctions, TaskMonitor monitor) throws Exception {
        Set<Function> result = new LinkedHashSet<>();
        for (Function function : selectedFunctions) {
            monitor.checkCancelled();
            var instructions = program.getListing().getInstructions(function.getBody(), true);
            while (instructions.hasNext()) {
                var flow = instructions.next().getFlowType();
                if (flow.isCall() && flow.isComputed()) {
                    result.add(function);
                    break;
                }
            }
        }
        return List.copyOf(result);
    }

    private static boolean ownedCallsite(Program program, Function function,
            Address callsite) {
        return callsite.isMemoryAddress() && function.getBody().contains(callsite) &&
                program.getMemory().getBlock(callsite) != null &&
                program.getListing().getInstructionAt(callsite) != null;
    }

    private static AnalysisStats empty(Outcome outcome, long started) {
        return empty(outcome, started, 0);
    }

    private static AnalysisStats empty(Outcome outcome, long started,
            long layoutNanos) {
        return new AnalysisStats(outcome, 0, 0, 0, 0, 0, 0, 0,
                DelegateCallRejectionCounts.none(), List.of(), List.of(),
                new PhaseTiming(layoutNanos, 0, 0, 0, 0),
                System.nanoTime() - started);
    }

    public enum Outcome {
        COMPLETE,
        DISABLED,
        MISSING_LAYOUT
    }

    public record ProvenCall(Address callsite, int typeId,
            String objectType, String signature) {
        public ProvenCall {
            Objects.requireNonNull(callsite, "callsite");
            if (typeId < 0 || objectType == null || objectType.isBlank() ||
                    signature == null || signature.isBlank()) {
                throw new IllegalArgumentException("invalid delegate-call proof");
            }
        }
    }

    public record RejectedCall(Address callsite,
            DelegateCallRejectionCounts.Reason reason) {
        public RejectedCall {
            Objects.requireNonNull(callsite, "callsite");
            Objects.requireNonNull(reason, "reason");
        }
    }

    public record PhaseTiming(long layoutNanos, long candidateSelectionNanos,
            long decompilationNanos, long resolutionNanos, long proofWallNanos) {
        public PhaseTiming {
            if (layoutNanos < 0 || candidateSelectionNanos < 0 ||
                    decompilationNanos < 0 || resolutionNanos < 0 || proofWallNanos < 0) {
                throw new IllegalArgumentException("delegate-call timing must not be negative");
            }
        }

        /** Includes overlapping worker durations, not elapsed time. */
        public long measuredNanos() {
            return Math.addExact(Math.addExact(layoutNanos, candidateSelectionNanos),
                    Math.addExact(decompilationNanos, resolutionNanos));
        }

        public long wallNanos() {
            return Math.addExact(Math.addExact(layoutNanos, candidateSelectionNanos),
                    proofWallNanos);
        }
    }

    public record AnalysisStats(Outcome outcome, int candidateFunctions,
            int completedFunctions, int failedFunctions, int indirectCalls,
            int delegateCandidates, int shapeRejected, int provenCalls,
            DelegateCallRejectionCounts rejections,
            List<RejectedCall> rejectionSamples, List<ProvenCall> proofs,
            PhaseTiming timing, long elapsedNanos) {
        public AnalysisStats {
            Objects.requireNonNull(outcome, "outcome");
            Objects.requireNonNull(rejections, "rejections");
            Objects.requireNonNull(timing, "timing");
            rejectionSamples = List.copyOf(rejectionSamples);
            proofs = List.copyOf(proofs);
            if (candidateFunctions < 0 || completedFunctions < 0 || failedFunctions < 0 ||
                    completedFunctions + failedFunctions > candidateFunctions ||
                    indirectCalls < 0 || delegateCandidates < 0 || shapeRejected < 0 ||
                    delegateCandidates > indirectCalls || provenCalls != proofs.size() ||
                    shapeRejected + provenCalls + rejections.total() != delegateCandidates ||
                    rejectionSamples.size() > MAX_REJECTION_SAMPLES ||
                    rejectionSamples.size() > rejections.total() ||
                    timing.wallNanos() > elapsedNanos || elapsedNanos < 0) {
                throw new IllegalArgumentException("invalid delegate-call statistics");
            }
        }

        public double elapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }
}
