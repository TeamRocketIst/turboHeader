package turboheader.il2cpp;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public final class Il2CppFunctionPreparationService {
    private Il2CppFunctionPreparationService() {
    }

    public static PreparationResult prepare(Program program,
            Il2CppExportPlanner.ExportPlan plan, TaskMonitor taskMonitor)
            throws CancelledException {
        Objects.requireNonNull(plan, "plan");
        return prepare(program, plan.classes(), taskMonitor);
    }

    static PreparationResult prepare(Program program,
            List<Il2CppExportPlanner.ClassPlan> classes, TaskMonitor taskMonitor)
            throws CancelledException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(classes, "classes");
        TaskMonitor monitor = taskMonitor == null ? TaskMonitor.DUMMY : taskMonitor;
        AutoAnalysisManager analysis = AutoAnalysisManager.getAnalysisManager(program);

        long references = 0;
        Map<Address, Function> unique = new LinkedHashMap<>();
        for (var classPlan : classes) {
            Objects.requireNonNull(classPlan, "class plan");
            for (Function function : classPlan.functions()) {
                monitor.checkCancelled();
                Objects.requireNonNull(function, "planned function");
                references++;
                unique.putIfAbsent(function.getEntryPoint(), function);
            }
        }

        List<Function> ordered = new ArrayList<>(unique.values());
        ordered.sort((left, right) -> Long.compareUnsigned(
                entryOffset(left), entryOffset(right)));

        long started = System.nanoTime();
        Map<Address, FunctionPreparation> byAddress = new LinkedHashMap<>();
        for (Function function : ordered) {
            monitor.checkCancelled();
            FunctionPreparation outcome;
            try {
                outcome = prepareFunction(program, function, analysis, monitor);
            }
            catch (RuntimeException error) {
                outcome = new FailedFunction(function, errorMessage(error));
            }
            byAddress.put(function.getEntryPoint(), outcome);
        }

        List<PreparedClassPlan> preparedClasses = new ArrayList<>(classes.size());
        for (var classPlan : classes) {
            List<FunctionPreparation> functions = new ArrayList<>(classPlan.functions().size());
            for (Function function : classPlan.functions()) {
                FunctionPreparation outcome = byAddress.get(function.getEntryPoint());
                if (outcome == null) {
                    throw new IllegalStateException("planned function was not prepared");
                }
                functions.add(outcome);
            }
            preparedClasses.add(new PreparedClassPlan(classPlan, functions));
        }

        int failures = (int) byAddress.values().stream()
                .filter(FailedFunction.class::isInstance)
                .count();
        return new PreparationResult(preparedClasses, new ArrayList<>(byAddress.values()),
                references, failures, System.nanoTime() - started);
    }

    private static FunctionPreparation prepareFunction(Program program, Function function,
            AutoAnalysisManager analysis, TaskMonitor monitor) throws CancelledException {
        var entryPoint = function.getEntryPoint();
        new DisassembleCommand(entryPoint, null, true).applyTo(program, monitor);
        monitor.checkCancelled();

        CreateFunctionCmd create = new CreateFunctionCmd(entryPoint);
        create.applyTo(program, monitor);
        monitor.checkCancelled();
        Function prepared = program.getFunctionManager().getFunctionAt(entryPoint);
        if (prepared == null) {
            prepared = function;
        }

        analyzeChanges(analysis, monitor);
        monitor.checkCancelled();
        return new PreparedFunction(function, prepared);
    }

    private static void analyzeChanges(AutoAnalysisManager analysis, TaskMonitor monitor) {
        PluginTool tool = analysis.getAnalysisTool();
        if (tool == null || tool.threadIsBackgroundTaskThread()) {
            analysis.startAnalysis(monitor, true);
        }
        else {
            analysis.waitForAnalysis(null, monitor);
        }
    }

    private static long entryOffset(Function function) {
        return function.getEntryPoint().getUnsignedOffset();
    }

    private static String errorMessage(RuntimeException error) {
        String message = error.getMessage();
        return message == null || message.isBlank() ? error.getClass().getSimpleName() : message;
    }

    public sealed interface FunctionPreparation permits PreparedFunction, FailedFunction {
        Function displayFunction();

        default long entryOffset() {
            return displayFunction().getEntryPoint().getUnsignedOffset();
        }
    }

    public record PreparedFunction(Function displayFunction, Function decompileFunction)
            implements FunctionPreparation {
        public PreparedFunction {
            Objects.requireNonNull(displayFunction, "displayFunction");
            Objects.requireNonNull(decompileFunction, "decompileFunction");
        }
    }

    public record FailedFunction(Function displayFunction, String error)
            implements FunctionPreparation {
        public FailedFunction {
            Objects.requireNonNull(displayFunction, "displayFunction");
            Objects.requireNonNull(error, "error");
        }
    }

    public record PreparedClassPlan(Il2CppExportPlanner.ClassPlan source,
            List<FunctionPreparation> functions) {
        public PreparedClassPlan {
            Objects.requireNonNull(source, "source");
            functions = List.copyOf(functions);
        }
    }

    public record PreparationResult(List<PreparedClassPlan> classes,
            List<FunctionPreparation> addressOrder, long functionReferences,
            int failedFunctions, long elapsedNanos) {
        public PreparationResult {
            classes = List.copyOf(classes);
            addressOrder = List.copyOf(addressOrder);
            if (functionReferences < addressOrder.size() || failedFunctions < 0 ||
                    failedFunctions > addressOrder.size() || elapsedNanos < 0) {
                throw new IllegalArgumentException("invalid preparation statistics");
            }
        }

        public int uniqueFunctions() {
            return addressOrder.size();
        }

        public int preparedFunctions() {
            return uniqueFunctions() - failedFunctions;
        }

        public double elapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }
}
