package turboheader.il2cpp.analysis;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import turboheader.il2cpp.metadata.Il2CppInterfaceDispatchCatalog;
import turboheader.il2cpp.metadata.Il2CppInterfaceDispatchStore;

public final class Il2CppInterfaceCallAnalyzer {
    private static final int DECOMPILE_TIMEOUT_SECONDS = 30;
    private static final int MAX_REJECTION_SAMPLES = 4;

    private Il2CppInterfaceCallAnalyzer() {
    }

    public static AnalysisStats analyze(Program program, List<Function> selectedFunctions,
            Map<Il2CppHelperKind, Address> helperAddresses, TaskMonitor taskMonitor)
            throws Exception {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(selectedFunctions, "selectedFunctions");
        Objects.requireNonNull(helperAddresses, "helperAddresses");
        TaskMonitor monitor = taskMonitor == null ? TaskMonitor.DUMMY : taskMonitor;
        long started = System.nanoTime();

        var stored = Il2CppInterfaceDispatchStore.read(program);
        if (stored.isEmpty()) {
            return empty(Outcome.DISABLED, started);
        }
        Address interfaceHelper = helperAddresses.get(
                Il2CppHelperKind.INTERFACE_INVOKE_LOOKUP);
        Address objectNewHelper = helperAddresses.get(Il2CppHelperKind.OBJECT_NEW);
        if (interfaceHelper == null || objectNewHelper == null) {
            return empty(Outcome.MISSING_HELPERS, started);
        }

        Set<Address> objectNewTargets = helperTargets(program, objectNewHelper);
        CandidateSelection selection = candidates(
                program, selectedFunctions, interfaceHelper, objectNewTargets, monitor);
        List<Function> candidates = selection.functions();
        if (candidates.isEmpty()) {
            return new AnalysisStats(Outcome.COMPLETE, 0,
                    selection.prefilteredFunctions(), 0, 0, 0, 0, 0, 0,
                    InterfaceCallRejectionCounts.none(), List.of(), List.of(),
                    System.nanoTime() - started);
        }

        long modificationNumber = program.getModificationNumber();
        var catalog = stored.orElseThrow();
        var typeInfoSources = GhidraTypeInfoSources.collect(program, catalog);
        var resolver = new GhidraPcodeInterfaceCallResolver(
                interfaceHelper, objectNewTargets, program.getDefaultPointerSize(),
                typeInfoSources, catalog);
        List<ProvenCall> proofs = new ArrayList<>();
        List<InterfaceCallRejectionCounts.Reason> rejectionReasons = new ArrayList<>();
        List<RejectedCall> rejectionSamples = new ArrayList<>();
        Set<Address> conflicts = new HashSet<>();
        Map<Address, ProvenCall> byCallsite = new LinkedHashMap<>();
        int completed = 0;
        int failed = 0;
        int helperCalls = 0;
        int associatedCalls = 0;

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.toggleCCode(false);
            if (!decompiler.openProgram(program)) {
                throw new IllegalStateException("Ghidra decompiler did not open the program");
            }
            for (Function candidate : candidates) {
                monitor.checkCancelled();
                var decompiled = decompiler.decompileFunction(
                        candidate, DECOMPILE_TIMEOUT_SECONDS, monitor);
                if (!decompiled.decompileCompleted() || decompiled.getHighFunction() == null) {
                    failed++;
                    continue;
                }
                completed++;
                var result = resolver.resolve(decompiled.getHighFunction());
                helperCalls += result.helperCalls();
                associatedCalls += result.associatedCalls();
                for (var call : result.calls()) {
                    if (call.resolution().proof().isEmpty()) {
                        var reason = InterfaceCallRejectionCounts.reason(
                                call.resolution().status());
                        rejectionReasons.add(reason);
                        if (rejectionSamples.size() < MAX_REJECTION_SAMPLES) {
                            Address helperCallsite = imageAddress(
                                    program, call.helperCallAddress(), false);
                            Address indirectCallsite = imageAddress(
                                    program, call.indirectCallAddress(), false);
                            if (helperCallsite != null && indirectCallsite != null) {
                                rejectionSamples.add(new RejectedCall(
                                        helperCallsite, indirectCallsite, reason));
                            }
                        }
                        continue;
                    }
                    var proof = call.resolution().proof().orElseThrow();
                    Address callsite = imageAddress(
                            program, proof.indirectCallAddress(), false);
                    Address target = imageAddress(program, proof.targetAddress(), true);
                    if (callsite == null || target == null || conflicts.contains(callsite)) {
                        continue;
                    }
                    var proven = new ProvenCall(callsite, target, proof.receiverTypeId(),
                            proof.interfaceTypeId(), proof.interfaceSlot());
                    ProvenCall previous = byCallsite.putIfAbsent(callsite, proven);
                    if (previous != null && !previous.equals(proven)) {
                        byCallsite.remove(callsite);
                        conflicts.add(callsite);
                    }
                }
            }
        }
        finally {
            decompiler.dispose();
        }

        if (program.getModificationNumber() != modificationNumber) {
            throw new IllegalStateException("interface-call proof changed the Ghidra program");
        }
        proofs.addAll(byCallsite.values());
        proofs.sort(Comparator.comparing(ProvenCall::callsite));
        return new AnalysisStats(Outcome.COMPLETE, candidates.size(),
                selection.prefilteredFunctions(), completed, failed,
                helperCalls, associatedCalls, proofs.size(), conflicts.size(),
                InterfaceCallRejectionCounts.count(rejectionReasons), rejectionSamples, proofs,
                System.nanoTime() - started);
    }

    private static Set<Address> helperTargets(Program program, Address canonicalAddress) {
        Function canonical = program.getFunctionManager().getFunctionAt(canonicalAddress);
        if (canonical == null) {
            return Set.of(canonicalAddress);
        }

        Set<Address> targets = new LinkedHashSet<>();
        targets.add(canonicalAddress);
        Address[] thunkAddresses = canonical.getFunctionThunkAddresses(true);
        if (thunkAddresses == null) {
            return Set.copyOf(targets);
        }
        for (Address address : thunkAddresses) {
            Function thunk = program.getFunctionManager().getFunctionAt(address);
            if (thunk != null && canonical.equals(thunk.getThunkedFunction(true))) {
                targets.add(address);
            }
        }
        return Set.copyOf(targets);
    }

    private static CandidateSelection candidates(Program program,
            List<Function> selectedFunctions, Address interfaceHelper,
            Set<Address> objectNewTargets, TaskMonitor monitor) throws Exception {
        Set<Function> unique = new LinkedHashSet<>();
        Set<Function> visited = new HashSet<>();
        int prefiltered = 0;
        for (Function function : selectedFunctions) {
            monitor.checkCancelled();
            if (!visited.add(function)) {
                continue;
            }
            var instructions = program.getListing().getInstructions(function.getBody(), true);
            boolean callsInterfaceHelper = false;
            boolean callsObjectNew = false;
            while (instructions.hasNext() &&
                    (!callsInterfaceHelper || !callsObjectNew)) {
                var instruction = instructions.next();
                if (!instruction.getFlowType().isCall()) {
                    continue;
                }
                for (Address flow : instruction.getFlows()) {
                    if (flow.equals(interfaceHelper)) {
                        callsInterfaceHelper = true;
                    }
                    if (objectNewTargets.contains(flow)) {
                        callsObjectNew = true;
                    }
                }
            }
            if (!callsInterfaceHelper) {
                continue;
            }
            if (callsObjectNew) {
                unique.add(function);
            }
            else {
                prefiltered++;
            }
        }
        return new CandidateSelection(List.copyOf(unique), prefiltered);
    }

    private static Address imageAddress(Program program, long offset, boolean requireFunction) {
        try {
            Address address = requireFunction
                    ? program.getImageBase().add(offset)
                    : program.getImageBase().getAddressSpace().getAddress(offset);
            if (program.getMemory().getBlock(address) == null) {
                return null;
            }
            if (requireFunction &&
                    program.getFunctionManager().getFunctionAt(address) == null) {
                return null;
            }
            return address;
        }
        catch (RuntimeException e) {
            return null;
        }
    }

    private static AnalysisStats empty(Outcome outcome, long started) {
        return new AnalysisStats(outcome, 0, 0, 0, 0, 0, 0, 0, 0,
                InterfaceCallRejectionCounts.none(), List.of(), List.of(),
                System.nanoTime() - started);
    }

    private record CandidateSelection(List<Function> functions, int prefilteredFunctions) {
        private CandidateSelection {
            functions = List.copyOf(functions);
            if (prefilteredFunctions < 0) {
                throw new IllegalArgumentException("prefilteredFunctions must not be negative");
            }
        }
    }

    public enum Outcome {
        COMPLETE,
        DISABLED,
        MISSING_HELPERS
    }

    public record ProvenCall(Address callsite, Address target, int receiverTypeId,
            int interfaceTypeId, int interfaceSlot) {
        public ProvenCall {
            Objects.requireNonNull(callsite, "callsite");
            Objects.requireNonNull(target, "target");
            if (receiverTypeId < 0 || interfaceTypeId < 0 || interfaceSlot < 0) {
                throw new IllegalArgumentException("interface-call proof must not be negative");
            }
        }
    }

    public record RejectedCall(Address helperCallsite, Address indirectCallsite,
            InterfaceCallRejectionCounts.Reason reason) {
        public RejectedCall {
            Objects.requireNonNull(helperCallsite, "helperCallsite");
            Objects.requireNonNull(indirectCallsite, "indirectCallsite");
            Objects.requireNonNull(reason, "reason");
        }
    }

    public record AnalysisStats(Outcome outcome, int candidateFunctions,
            int prefilteredFunctions, int completedFunctions, int failedFunctions,
            int helperCalls, int associatedCalls, int provenCalls, int conflictingCallsites,
            InterfaceCallRejectionCounts rejections, List<RejectedCall> rejectionSamples,
            List<ProvenCall> proofs, long elapsedNanos) {
        public AnalysisStats {
            Objects.requireNonNull(outcome, "outcome");
            Objects.requireNonNull(rejections, "rejections");
            rejectionSamples = List.copyOf(rejectionSamples);
            proofs = List.copyOf(proofs);
            if (candidateFunctions < 0 || prefilteredFunctions < 0 ||
                    completedFunctions < 0 || failedFunctions < 0 ||
                    completedFunctions + failedFunctions > candidateFunctions ||
                    helperCalls < 0 || associatedCalls < 0 || provenCalls < 0 ||
                    conflictingCallsites < 0 || associatedCalls > helperCalls ||
                    provenCalls != proofs.size() ||
                    rejections.total() > associatedCalls ||
                    rejectionSamples.size() > MAX_REJECTION_SAMPLES ||
                    rejectionSamples.size() > rejections.total() || elapsedNanos < 0) {
                throw new IllegalArgumentException("invalid interface-call statistics");
            }
        }

        public double elapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }
}
