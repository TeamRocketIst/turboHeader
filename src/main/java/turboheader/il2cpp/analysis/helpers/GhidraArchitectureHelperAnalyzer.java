package turboheader.il2cpp.analysis.helpers;

import java.util.ArrayList;
import java.util.List;
import java.util.OptionalInt;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;
import turboheader.il2cpp.analysis.architecture.ArchitectureHelperProof;
import turboheader.il2cpp.analysis.architecture.Il2CppArchitectureSupport;
import turboheader.il2cpp.project.Il2CppProgramFacts;

final class GhidraArchitectureHelperAnalyzer {
    private final Program program;
    private final List<Function> selectedFunctions;
    private final TaskMonitor monitor;
    private final Address imageBase;

    GhidraArchitectureHelperAnalyzer(Program program, List<Function> selectedFunctions,
            TaskMonitor monitor) {
        this.program = program;
        this.selectedFunctions = List.copyOf(selectedFunctions);
        this.monitor = monitor;
        this.imageBase = program.getImageBase();
    }

    AnalysisResult analyze() throws Exception {
        long started = System.nanoTime();
        var support = Il2CppArchitectureSupport.inspect(program);
        if (support.helperProof().isEmpty()) {
            return empty(Outcome.UNSUPPORTED, started);
        }

        Set<Long> managedMethods = Il2CppProgramFacts.readManagedMethods(program);
        if (managedMethods.isEmpty()) {
            return empty(Outcome.MISSING_MANAGED_METHODS, started);
        }

        List<ArchitectureHelperProof.ManagedMethod> methods = new ArrayList<>();
        long instructionCount = 0;
        ExecutableWords words = new ExecutableWords();
        for (Function function : selectedFunctions) {
            monitor.checkCancelled();
            ArchitectureHelperProof.ManagedMethod method = readMethod(function, words);
            if (method != null) {
                methods.add(method);
                instructionCount += method.instructions().size();
            }
        }
        monitor.checkCancelled();
        var input = new ArchitectureHelperProof.Input(methods, managedMethods, words);
        var proof = support.helperProof().orElseThrow().analyze(input);
        monitor.checkCancelled();
        return new AnalysisResult(Outcome.COMPLETE, methods.size(), instructionCount,
                proof, System.nanoTime() - started);
    }

    private ArchitectureHelperProof.ManagedMethod readMethod(Function function,
            ExecutableWords words) {
        if (function.getBody().isEmpty()) {
            return null;
        }
        Long entry = offset(function.getEntryPoint());
        Long maximum = offset(function.getBody().getMaxAddress());
        if (entry == null || maximum == null) {
            return null;
        }
        long endExclusive = maximum + 1;
        if (Long.compareUnsigned(endExclusive, maximum) < 0 ||
                Long.compareUnsigned(entry, endExclusive) >= 0) {
            return null;
        }

        List<ArchitectureHelperProof.InstructionWord> instructions = new ArrayList<>();
        var iterator = program.getListing().getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            var instruction = iterator.next();
            if (instruction.getLength() != Integer.BYTES) {
                continue;
            }
            Long address = offset(instruction.getAddress());
            if (address == null) {
                continue;
            }
            OptionalInt encoding = words.read(address);
            encoding.ifPresent(value -> instructions.add(
                    new ArchitectureHelperProof.InstructionWord(address, value)));
        }
        return new ArchitectureHelperProof.ManagedMethod(entry, endExclusive, instructions);
    }

    private Long offset(Address address) {
        if (!address.getAddressSpace().equals(imageBase.getAddressSpace())) {
            return null;
        }
        try {
            long result = address.subtract(imageBase);
            return result < 0 ? null : result;
        }
        catch (RuntimeException e) {
            return null;
        }
    }

    private AnalysisResult empty(Outcome outcome, long started) {
        var proof = new ArchitectureHelperProof.Result(List.of(), 0, 0, 0);
        return new AnalysisResult(outcome, 0, 0, proof, System.nanoTime() - started);
    }

    enum Outcome {
        COMPLETE,
        UNSUPPORTED,
        MISSING_MANAGED_METHODS
    }

    record AnalysisResult(Outcome outcome, int scannedMethods, long scannedInstructions,
            ArchitectureHelperProof.Result proof, long elapsedNanos) {
        double elapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }

    private final class ExecutableWords implements ArchitectureHelperProof.ExecutableWords {
        @Override
        public OptionalInt read(long rawAddress) {
            Address address = address(rawAddress);
            if (address == null || !isExecutable(address)) {
                return OptionalInt.empty();
            }
            try {
                return OptionalInt.of(program.getMemory().getInt(address));
            }
            catch (MemoryAccessException | RuntimeException e) {
                return OptionalInt.empty();
            }
        }

        @Override
        public boolean isExecutable(long rawAddress) {
            Address address = address(rawAddress);
            return address != null && isExecutable(address);
        }

        private Address address(long rawAddress) {
            if (rawAddress < 0) {
                return null;
            }
            try {
                return imageBase.add(rawAddress);
            }
            catch (RuntimeException e) {
                return null;
            }
        }

        private boolean isExecutable(Address address) {
            var block = program.getMemory().getBlock(address);
            return block != null && block.isExecute();
        }
    }
}
