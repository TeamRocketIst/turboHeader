package turboheader.il2cpp.exporting;

import java.io.BufferedWriter;
import java.io.IOException;
import java.util.Objects;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import turboheader.il2cpp.Il2CppExportPlanner;
import turboheader.il2cpp.decompile.Il2CppDecompilationCoordinator;
import turboheader.il2cpp.decompile.Il2CppFunctionMatcher;

public final class Il2CppExportWriter {
    private static final String SEPARATOR =
            "// ---------------------------------------------------------------------\n";

    private Il2CppExportWriter() {
    }

    public static WriteResult write(Program program, Il2CppExportPlanner.ExportPlan plan,
            Il2CppDecompilationCoordinator.DecompilationResult decompilation,
            PhaseTimings timings, TaskMonitor taskMonitor)
            throws IOException, CancelledException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(decompilation, "decompilation");
        Objects.requireNonNull(timings, "timings");
        TaskMonitor monitor = taskMonitor == null ? TaskMonitor.DUMMY : taskMonitor;
        validatePlan(plan, decompilation);

        long modification = program.getModificationNumber();
        long started = System.nanoTime();
        Il2CppOutputDirectory output = Il2CppOutputDirectory.open(plan.request().output());
        long bytesWritten = 0;

        long classStarted = System.nanoTime();
        for (var classResult : decompilation.classes()) {
            monitor.checkCancelled();
            bytesWritten += output.write(classResult.source().relativeOutput(),
                    writer -> writeClass(writer, program, classResult, monitor));
        }
        long classWritingNanos = System.nanoTime() - classStarted;
        long totalExportNanos = timings.elapsedBeforeWritingNanos() + classWritingNanos;

        var reports = Il2CppExportReports.write(output, program, plan, decompilation,
                timings, classWritingNanos, totalExportNanos, monitor);
        bytesWritten += reports.bytesWritten();

        if (program.getModificationNumber() != modification) {
            throw new IllegalStateException("export writing modified the Ghidra program");
        }
        return new WriteResult(decompilation.classes().size(), decompilation.completedFunctions(),
                decompilation.failedFunctions(), bytesWritten, classWritingNanos,
                reports.elapsedNanos(), System.nanoTime() - started);
    }

    private static void validatePlan(Il2CppExportPlanner.ExportPlan plan,
            Il2CppDecompilationCoordinator.DecompilationResult decompilation) {
        if (plan.classes().size() != decompilation.classes().size()) {
            throw new IllegalArgumentException("class result count differs from the export plan");
        }
        for (int classIndex = 0; classIndex < plan.classes().size(); classIndex++) {
            var plannedClass = plan.classes().get(classIndex);
            var classResult = decompilation.classes().get(classIndex);
            if (!plannedClass.equals(classResult.source())) {
                throw new IllegalArgumentException(
                        "class result order differs from the export plan");
            }
            if (plannedClass.functions().size() != classResult.functions().size()) {
                throw new IllegalArgumentException(
                        "function result count differs from the class plan");
            }
            for (int functionIndex = 0;
                    functionIndex < plannedClass.functions().size(); functionIndex++) {
                Function planned = plannedClass.functions().get(functionIndex);
                Function actual = classResult.functions().get(functionIndex).displayFunction();
                if (!planned.getEntryPoint().equals(actual.getEntryPoint())) {
                    throw new IllegalArgumentException(
                            "function result order differs from the class plan");
                }
            }
        }
    }

    private static void writeClass(BufferedWriter writer, Program program,
            Il2CppDecompilationCoordinator.DecompiledClassPlan classResult,
            TaskMonitor monitor) throws IOException, CancelledException {
        var entry = classResult.source().classEntry();
        Il2CppExportText.line(writer, "// Decompiled with Ghidra from program: " +
                Il2CppExportText.singleLine(program.getName()));
        Il2CppExportText.line(writer, "// cpp2il assembly: " +
                Il2CppExportText.singleLine(entry.assembly()));
        Il2CppExportText.line(writer, "// cpp2il class file: " +
                Il2CppExportText.singleLine(entry.relativeSource()));
        Il2CppExportText.line(writer, "// class name from filename: " +
                Il2CppExportText.singleLine(entry.className()));
        Il2CppExportText.line(writer, "// namespace from folder path: " +
                Il2CppExportText.singleLine(entry.namespaceName()));
        writer.write('\n');

        if (classResult.functions().isEmpty()) {
            Il2CppExportText.line(writer,
                    "// No Ghidra functions matched this cpp2il class.");
            return;
        }

        for (var outcome : classResult.functions()) {
            monitor.checkCancelled();
            Function function = outcome.displayFunction();
            writer.write('\n');
            writer.write(SEPARATOR);
            Il2CppExportText.line(writer, "// Function: " +
                    Il2CppExportText.functionName(function));
            Il2CppExportText.line(writer, "// Address : " + function.getEntryPoint());
            writer.write(SEPARATOR);

            if (outcome instanceof Il2CppDecompilationCoordinator.DecompiledFunction completed) {
                String code = completed.result().getCCode();
                writer.write(code);
                if (!code.endsWith("\n")) {
                    writer.write('\n');
                }
                continue;
            }

            var failure = (Il2CppDecompilationCoordinator.FunctionFailure) outcome;
            String prefix = failure.stage() ==
                    Il2CppDecompilationCoordinator.FailureStage.PREPARATION
                            ? "// Decompilation exception: "
                            : "// Decompilation failed: ";
            Il2CppExportText.line(writer,
                    prefix + Il2CppExportText.singleLine(failure.error()));
        }
    }

    public record PhaseTimings(long scanNanos, long analysisNanos,
            long preparationNanos, long decompilationNanos,
            long elapsedBeforeWritingNanos) {
        public PhaseTimings {
            if (scanNanos < 0 || analysisNanos < 0 || preparationNanos < 0 ||
                    decompilationNanos < 0 || elapsedBeforeWritingNanos < 0) {
                throw new IllegalArgumentException("phase timings must not be negative");
            }
        }
    }

    public record WriteResult(int classFiles, int completedFunctions,
            int failedFunctions, long bytesWritten, long classWritingNanos,
            long reportWritingNanos, long elapsedNanos) {
        public WriteResult {
            if (classFiles < 0 || completedFunctions < 0 || failedFunctions < 0 ||
                    bytesWritten < 0 || classWritingNanos < 0 ||
                    reportWritingNanos < 0 || elapsedNanos < 0) {
                throw new IllegalArgumentException("write statistics must not be negative");
            }
        }

        public double elapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }
}
