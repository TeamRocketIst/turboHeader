package turboheader.il2cpp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/** Discovers the returning IL2CPP runtime-metadata initializer from typed call arguments. */
public final class Il2CppRuntimeMetadataAnalyzer {
    private static final int DECOMPILE_TIMEOUT_SECONDS = 30;
    private Il2CppRuntimeMetadataAnalyzer() {
    }

    public static AnalysisStats analyze(Program program, TaskMonitor taskMonitor)
            throws Exception {
        TaskMonitor monitor = taskMonitor == null ? TaskMonitor.DUMMY : taskMonitor;
        long started = System.nanoTime();
        Set<Address> probes = Il2CppProgramFacts.readRuntimeMetadataProbes(program);
        Set<Address> metadataSlots = Il2CppProgramFacts.readRuntimeMetadataSlots(program);
        if (probes.isEmpty() || metadataSlots.isEmpty()) {
            return new AnalysisStats(probes.size(), metadataSlots.size(), 0, null,
                    RenameOutcome.NOT_FOUND, 0, 0, 0, Map.of(),
                    System.nanoTime() - started);
        }

        Set<Long> managedRaw = Il2CppProgramFacts.readManagedMethods(program);
        Address imageBase = program.getImageBase();
        Map<Address, Integer> candidates = new HashMap<>();
        int completedProbes = 0;
        int callOperations = 0;
        int singleArgumentCalls = 0;
        int metadataArgumentCalls = 0;

        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(program)) {
                throw new IllegalStateException("Ghidra decompiler did not open the program");
            }
            List<Address> orderedProbes = new ArrayList<>(probes);
            orderedProbes.sort(Address::compareTo);
            for (Address probeAddress : orderedProbes) {
                monitor.checkCancelled();
                Function probe = prepareFunction(program, probeAddress, monitor);
                var result = decompiler.decompileFunction(
                        probe, DECOMPILE_TIMEOUT_SECONDS, monitor);
                if (!result.decompileCompleted() || result.getHighFunction() == null) {
                    continue;
                }
                completedProbes++;
                var operations = result.getHighFunction().getPcodeOps();
                while (operations.hasNext()) {
                    PcodeOpAST operation = operations.next();
                    if (operation.getOpcode() != PcodeOp.CALL) {
                        continue;
                    }
                    Address callsite = operation.getSeqnum().getTarget();
                    if (callsite == null || !probe.getBody().contains(callsite)) {
                        continue;
                    }
                    callOperations++;
                    if (operation.getNumInputs() != 2) {
                        continue;
                    }
                    singleArgumentCalls++;
                    Address target = operation.getInput(0).getAddress();
                    if (target == null ||
                            !PcodeValueTracer.referencesAny(
                                    operation.getInput(1), metadataSlots) ||
                            managedRaw.contains(target.subtract(imageBase))) {
                        continue;
                    }
                    metadataArgumentCalls++;
                    var block = program.getMemory().getBlock(target);
                    if (block != null && block.isExecute()) {
                        candidates.merge(target, 1, Integer::sum);
                    }
                }
            }
        }
        finally {
            decompiler.dispose();
        }

        if (candidates.size() != 1) {
            return new AnalysisStats(probes.size(), metadataSlots.size(), completedProbes, null,
                    candidates.isEmpty() ? RenameOutcome.NOT_FOUND : RenameOutcome.AMBIGUOUS,
                    callOperations, singleArgumentCalls, metadataArgumentCalls,
                    Map.copyOf(candidates),
                    System.nanoTime() - started);
        }

        Address helperAddress = candidates.keySet().iterator().next();
        RenameOutcome outcome = applyHelperIdentity(program, helperAddress, monitor);
        return new AnalysisStats(probes.size(), metadataSlots.size(), completedProbes,
                helperAddress, outcome, callOperations, singleArgumentCalls,
                metadataArgumentCalls, Map.copyOf(candidates),
                System.nanoTime() - started);
    }

    private static Function prepareFunction(Program program, Address address, TaskMonitor monitor)
            throws Exception {
        DisassembleCommand disassemble = new DisassembleCommand(address, null, true);
        disassemble.enableCodeAnalysis(false);
        disassemble.applyTo(program, monitor);
        Function function = program.getFunctionManager().getFunctionAt(address);
        if (function == null) {
            CreateFunctionCmd create = new CreateFunctionCmd(address);
            if (!create.applyTo(program, monitor)) {
                throw new IllegalStateException("Could not create runtime-metadata probe at " +
                        address + ": " + create.getStatusMsg());
            }
            function = program.getFunctionManager().getFunctionAt(address);
        }
        if (function == null) {
            throw new IllegalStateException("No runtime-metadata probe function at " + address);
        }
        CreateFunctionCmd.fixupFunctionBody(program, function, monitor);
        return function;
    }

    private static RenameOutcome applyHelperIdentity(Program program, Address address,
            TaskMonitor monitor) throws Exception {
        Function helper = prepareFunction(program, address, monitor);
        String expected = Il2CppHelperNames.mappedName(
                Il2CppHelperKind.METADATA_INIT, address.getOffset());
        boolean alreadyNamed = expected.equals(helper.getName());
        SourceType source = helper.getSymbol().getSource();
        if (!alreadyNamed &&
                source != SourceType.DEFAULT && source != SourceType.ANALYSIS) {
            return RenameOutcome.PRESERVED;
        }

        FunctionDefinitionDataType signature = new FunctionDefinitionDataType(
                GhidraMethodImporter.SIGNATURES, expected, program.getDataTypeManager());
        signature.setReturnType(VoidDataType.dataType);
        signature.setArguments(new ParameterDefinitionImpl("metadataPointer",
                program.getDataTypeManager().getPointer(
                        VoidDataType.dataType, program.getDefaultPointerSize()), null));
        var defaultConvention = program.getCompilerSpec().getDefaultCallingConvention();
        if (defaultConvention != null) {
            signature.setCallingConvention(defaultConvention.getName());
        }

        helper.setName(expected, SourceType.ANALYSIS);
        ApplyFunctionSignatureCmd command = new ApplyFunctionSignatureCmd(address, signature,
                SourceType.ANALYSIS, false, false, DataTypeConflictHandler.REPLACE_HANDLER,
                FunctionRenameOption.NO_CHANGE);
        if (!command.applyTo(program, monitor)) {
            throw new IllegalStateException("Could not type runtime-metadata helper at " +
                    address + ": " + command.getStatusMsg());
        }
        return alreadyNamed ? RenameOutcome.ALREADY_NAMED : RenameOutcome.RENAMED;
    }

    public enum RenameOutcome {
        RENAMED,
        ALREADY_NAMED,
        PRESERVED,
        NOT_FOUND,
        AMBIGUOUS
    }

    public record AnalysisStats(int probes, int metadataSlots, int completedProbes,
            Address helperAddress, RenameOutcome outcome, int callOperations,
            int singleArgumentCalls, int metadataArgumentCalls,
            Map<Address, Integer> candidateCalls, long elapsedNanos) {
        public double elapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }
}
