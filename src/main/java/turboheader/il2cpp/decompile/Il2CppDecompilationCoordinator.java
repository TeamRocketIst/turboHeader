package turboheader.il2cpp.decompile;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import turboheader.il2cpp.Il2CppExportPlanner;

public final class Il2CppDecompilationCoordinator {
    private Il2CppDecompilationCoordinator() {
    }

    public static DecompilationResult decompile(Program program,
            Il2CppFunctionPreparationService.PreparationResult preparation,
            int workerCount, TaskMonitor taskMonitor) throws Exception {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(preparation, "preparation");
        if (workerCount < Il2CppDecompilationPolicy.MIN_PARALLEL_WORKERS ||
                workerCount > Il2CppDecompilationPolicy.MAX_WORKERS) {
            throw new IllegalArgumentException("workerCount must be between 1 and 12");
        }

        TaskMonitor monitor = taskMonitor == null ? TaskMonitor.DUMMY : taskMonitor;
        List<Il2CppFunctionPreparationService.PreparedFunction> submitted = new ArrayList<>();
        for (var function : preparation.addressOrder()) {
            monitor.checkCancelled();
            if (function instanceof Il2CppFunctionPreparationService.PreparedFunction ready) {
                submitted.add(ready);
            }
        }

        Optional<Il2CppDecompilerService.BatchResult> batch = Optional.empty();
        if (!submitted.isEmpty()) {
            List<Function> functions = submitted.stream()
                    .map(Il2CppFunctionPreparationService.PreparedFunction::decompileFunction)
                    .toList();
            batch = Optional.of(Il2CppDecompilerService.decompileFunctions(
                    program, functions, workerCount,
                    Il2CppDecompilationPolicy.TIMEOUT_SECONDS, monitor));
        }
        monitor.checkCancelled();

        Map<Address, FunctionOutcome> byAddress = mapOutcomes(preparation, submitted, batch);
        List<DecompiledClassPlan> classes = new ArrayList<>(preparation.classes().size());
        for (var classPlan : preparation.classes()) {
            List<FunctionOutcome> functions = new ArrayList<>(classPlan.functions().size());
            for (var function : classPlan.functions()) {
                FunctionOutcome outcome = byAddress.get(function.displayFunction().getEntryPoint());
                if (outcome == null) {
                    throw new IllegalStateException("prepared function has no decompilation result");
                }
                functions.add(outcome);
            }
            classes.add(new DecompiledClassPlan(classPlan.source(), functions));
        }

        return new DecompilationResult(classes, new ArrayList<>(byAddress.values()),
                submitted.size(), batch);
    }

    private static Map<Address, FunctionOutcome> mapOutcomes(
            Il2CppFunctionPreparationService.PreparationResult preparation,
            List<Il2CppFunctionPreparationService.PreparedFunction> submitted,
            Optional<Il2CppDecompilerService.BatchResult> batch) {
        Map<Address, Il2CppDecompilerService.FunctionResult> decompiled = new LinkedHashMap<>();
        if (batch.isPresent()) {
            List<Il2CppDecompilerService.FunctionResult> results = batch.orElseThrow().getResults();
            if (results.size() != submitted.size()) {
                throw new IllegalStateException("decompiler result count differs from submission count");
            }
            for (int index = 0; index < results.size(); index++) {
                var prepared = submitted.get(index);
                var result = results.get(index);
                Address address = prepared.displayFunction().getEntryPoint();
                if (!address.equals(result.getEntryPoint())) {
                    throw new IllegalStateException("decompiler result order differs from submission order");
                }
                decompiled.put(address, result);
            }
        }

        Map<Address, FunctionOutcome> outcomes = new LinkedHashMap<>();
        for (var function : preparation.addressOrder()) {
            Address address = function.displayFunction().getEntryPoint();
            FunctionOutcome outcome;
            if (function instanceof Il2CppFunctionPreparationService.FailedFunction failure) {
                outcome = new FunctionFailure(failure.displayFunction(),
                        FailureStage.PREPARATION, failure.error(), false, 0);
            }
            else {
                var prepared = (Il2CppFunctionPreparationService.PreparedFunction) function;
                var result = decompiled.get(address);
                if (result == null) {
                    throw new IllegalStateException("submitted function has no decompiler result");
                }
                if (result.isCompleted()) {
                    outcome = new DecompiledFunction(prepared, result);
                }
                else {
                    outcome = new FunctionFailure(prepared.displayFunction(),
                            FailureStage.DECOMPILATION, result.getErrorMessage(),
                            result.isRetried(), result.getElapsedNanos());
                }
            }
            if (outcomes.put(address, outcome) != null) {
                throw new IllegalStateException("preparation contains a duplicate entry address");
            }
        }
        return outcomes;
    }

    public enum FailureStage {
        PREPARATION,
        DECOMPILATION
    }

    public sealed interface FunctionOutcome permits DecompiledFunction, FunctionFailure {
        Function displayFunction();
    }

    public record DecompiledFunction(
            Il2CppFunctionPreparationService.PreparedFunction preparation,
            Il2CppDecompilerService.FunctionResult result) implements FunctionOutcome {
        public DecompiledFunction {
            Objects.requireNonNull(preparation, "preparation");
            Objects.requireNonNull(result, "result");
            if (!result.isCompleted()) {
                throw new IllegalArgumentException("decompiler result did not complete");
            }
            if (!preparation.displayFunction().getEntryPoint().equals(result.getEntryPoint())) {
                throw new IllegalArgumentException("prepared and decompiled functions differ");
            }
        }

        @Override
        public Function displayFunction() {
            return preparation.displayFunction();
        }
    }

    public record FunctionFailure(Function displayFunction, FailureStage stage,
            String error, boolean retryAttempted, long elapsedNanos) implements FunctionOutcome {
        public FunctionFailure {
            Objects.requireNonNull(displayFunction, "displayFunction");
            Objects.requireNonNull(stage, "stage");
            Objects.requireNonNull(error, "error");
            if (error.isBlank()) {
                throw new IllegalArgumentException("failure message must not be blank");
            }
            if (elapsedNanos < 0) {
                throw new IllegalArgumentException("failure elapsed time must not be negative");
            }
        }
    }

    public record DecompiledClassPlan(Il2CppExportPlanner.ClassPlan source,
            List<FunctionOutcome> functions) {
        public DecompiledClassPlan {
            Objects.requireNonNull(source, "source");
            functions = List.copyOf(functions);
        }
    }

    public record DecompilationResult(List<DecompiledClassPlan> classes,
            List<FunctionOutcome> addressOrder, int submittedFunctions,
            Optional<Il2CppDecompilerService.BatchResult> batch) {
        public DecompilationResult {
            classes = List.copyOf(classes);
            addressOrder = List.copyOf(addressOrder);
            batch = Objects.requireNonNull(batch, "batch");
            if (submittedFunctions < 0 || submittedFunctions > addressOrder.size()) {
                throw new IllegalArgumentException("invalid decompilation statistics");
            }
            if ((submittedFunctions == 0) != batch.isEmpty()) {
                throw new IllegalArgumentException("decompiler batch does not match submissions");
            }
            if (batch.isPresent() &&
                    batch.orElseThrow().getResults().size() != submittedFunctions) {
                throw new IllegalArgumentException("decompiler batch size differs from submissions");
            }
        }

        public int completedFunctions() {
            return (int) addressOrder.stream().filter(DecompiledFunction.class::isInstance).count();
        }

        public int failedFunctions() {
            return addressOrder.size() - completedFunctions();
        }
    }
}
