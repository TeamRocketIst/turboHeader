package turboheader.il2cpp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Java-owned IL2CPP noreturn pipeline.
 *
 * <p>A non-empty i2c seed file is always the fast path. Only generators without that artifact run
 * local conservative discovery. Both inputs share validation, Ghidra application, call override,
 * and caller repair.</p>
 */
public final class Il2CppNoreturnAnalyzer {
    private Il2CppNoreturnAnalyzer() {
    }

    public static AnalysisStats analyze(Program program, String seedPath, TaskMonitor taskMonitor)
            throws Exception {
        TaskMonitor monitor = taskMonitor == null ? TaskMonitor.DUMMY : taskMonitor;
        long totalStarted = System.nanoTime();
        long discoveryStarted = System.nanoTime();
        NoreturnSeedReader.SeedInput input = NoreturnSeedReader.load(seedPath);
        Set<Long> managed = Il2CppProgramFacts.readManagedMethods(program);
        Set<Long> proven;
        Set<Long> provenHelpers;
        String source;
        int helperSummaries = 0;
        long managedInstructions = 0;
        long helperInstructions = 0;
        if (input.usable()) {
            proven = input.addresses();
            // The legacy seed format contains addresses only and does not distinguish
            // terminal imports from transitive helpers. Do not guess names in this lane.
            provenHelpers = Set.of();
            source = "i2c-seeds";
        }
        else {
            if (managed.isEmpty()) {
                throw new IllegalStateException(
                        "No imported IL2CPP managed-method facts are present in this Ghidra program");
            }
            var discovery = new GhidraNoreturnDiscovery(program).discover(managed);
            proven = discovery.proven();
            provenHelpers = discovery.provenHelpers();
            helperSummaries = discovery.helperSummaries();
            managedInstructions = discovery.managedInstructions();
            helperInstructions = discovery.helperInstructions();
            source = "ghidra-local";
        }
        long discoveryNanos = System.nanoTime() - discoveryStarted;

        long applicationStarted = System.nanoTime();
        ApplicationStats applied = apply(program, proven, provenHelpers, monitor);
        long applicationNanos = System.nanoTime() - applicationStarted;
        return new AnalysisStats(source, proven.size(), applied.markedFunctions(),
                applied.callOverrides(), applied.repairedCallers(), helperSummaries,
                managedInstructions, helperInstructions, provenHelpers.size(),
                applied.helpersRenamed(), applied.helperNamesAlreadyApplied(),
                applied.helperNamesPreserved(), discoveryNanos, applicationNanos,
                System.nanoTime() - totalStarted);
    }

    private static ApplicationStats apply(Program program, Set<Long> rawAddresses,
            Set<Long> helperAddresses, TaskMonitor monitor) throws Exception {
        Address imageBase = program.getImageBase();
        List<ProvenAddress> validatedAddresses = new ArrayList<>();
        for (long rawAddress : NoreturnSeedReader.ordered(rawAddresses)) {
            monitor.checkCancelled();
            Address address = imageBase.add(rawAddress);
            var block = program.getMemory().getBlock(address);
            if (block == null || !block.isExecute()) {
                throw new IllegalArgumentException(String.format(
                        "Noreturn address 0x%x is not in executable program memory", rawAddress));
            }
            validatedAddresses.add(new ProvenAddress(address,
                    helperAddresses.contains(rawAddress)));
        }

        List<Function> marked = new ArrayList<>();
        GhidraHelperFunctionNamer namer = new GhidraHelperFunctionNamer();
        int helpersRenamed = 0;
        int helperNamesAlreadyApplied = 0;
        int helperNamesPreserved = 0;
        for (ProvenAddress provenAddress : validatedAddresses) {
            monitor.checkCancelled();
            Function function = ensureFunction(program, provenAddress.address(), monitor);
            function.setNoReturn(true);
            if (provenAddress.helper()) {
                switch (namer.rename(function, Il2CppHelperKind.THROW)) {
                    case RENAMED -> helpersRenamed++;
                    case ALREADY_NAMED -> helperNamesAlreadyApplied++;
                    case PRESERVED -> helperNamesPreserved++;
                }
            }
            marked.add(function);
        }

        Map<Address, Instruction> callsites = new HashMap<>();
        Map<Address, Function> callers = new HashMap<>();
        var references = program.getReferenceManager();
        var listing = program.getListing();
        for (Function target : marked) {
            var incoming = references.getReferencesTo(target.getEntryPoint());
            while (incoming.hasNext()) {
                var reference = incoming.next();
                if (!reference.getReferenceType().isCall()) {
                    continue;
                }
                Instruction instruction = listing.getInstructionAt(reference.getFromAddress());
                if (instruction == null || instruction.getDefaultFallThrough() == null ||
                        !contains(instruction.getDefaultFlows(), target.getEntryPoint())) {
                    continue;
                }
                callsites.put(instruction.getAddress(), instruction);
                Function caller = program.getFunctionManager().getFunctionContaining(
                        instruction.getAddress());
                if (caller != null) {
                    callers.put(caller.getEntryPoint(), caller);
                }
            }
        }
        for (Instruction callsite : callsites.values()) {
            callsite.setFlowOverride(FlowOverride.CALL_RETURN);
        }
        int repaired = 0;
        for (Function caller : callers.values()) {
            monitor.checkCancelled();
            if (CreateFunctionCmd.fixupFunctionBody(program, caller, monitor)) {
                repaired++;
            }
        }
        return new ApplicationStats(marked.size(), callsites.size(), repaired,
                helpersRenamed, helperNamesAlreadyApplied, helperNamesPreserved);
    }

    private static Function ensureFunction(Program program, Address address, TaskMonitor monitor) {
        Function existing = program.getFunctionManager().getFunctionAt(address);
        if (existing != null) {
            return existing;
        }
        DisassembleCommand disassemble = new DisassembleCommand(address, null, true);
        disassemble.enableCodeAnalysis(false);
        disassemble.applyTo(program, monitor);
        CreateFunctionCmd create = new CreateFunctionCmd(address);
        if (!create.applyTo(program, monitor)) {
            throw new IllegalStateException(
                    "Could not create noreturn function at " + address + ": " + create.getStatusMsg());
        }
        Function created = program.getFunctionManager().getFunctionAt(address);
        if (created == null) {
            throw new IllegalStateException("Noreturn function creation produced no function at " + address);
        }
        return created;
    }

    private static boolean contains(Address[] addresses, Address expected) {
        for (Address address : addresses) {
            if (address.equals(expected)) {
                return true;
            }
        }
        return false;
    }

    private record ProvenAddress(Address address, boolean helper) {
    }

    private record ApplicationStats(int markedFunctions, int callOverrides, int repairedCallers,
            int helpersRenamed, int helperNamesAlreadyApplied, int helperNamesPreserved) {
    }

    public record AnalysisStats(String source, int provenAddresses, int markedFunctions,
            int callOverrides, int repairedCallers, int helperSummaries,
            long managedInstructions, long helperInstructions, int provenHelpers,
            int helpersRenamed, int helperNamesAlreadyApplied, int helperNamesPreserved,
            long discoveryNanos, long applicationNanos, long totalNanos) {
        public double discoverySeconds() {
            return discoveryNanos / 1_000_000_000.0;
        }

        public double applicationSeconds() {
            return applicationNanos / 1_000_000_000.0;
        }

        public double totalSeconds() {
            return totalNanos / 1_000_000_000.0;
        }
    }
}
