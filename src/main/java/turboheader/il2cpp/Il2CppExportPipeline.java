package turboheader.il2cpp;

import java.util.Locale;
import java.util.Objects;
import java.util.function.Consumer;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import turboheader.il2cpp.analysis.Il2CppExportAnalysisService;
import turboheader.il2cpp.analysis.Il2CppNoreturnAnalyzer;

public final class Il2CppExportPipeline {
    private Il2CppExportPipeline() {
    }

    public static PipelineResult run(Program program,
            HeadlessRequestReader.ExportRequest request, TaskMonitor taskMonitor,
            Consumer<String> progress) throws Exception {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(request, "request");
        if (request.decompileJobs() < Il2CppDecompilationPolicy.MIN_PARALLEL_WORKERS ||
                request.decompileJobs() > Il2CppDecompilationPolicy.MAX_WORKERS) {
            throw new IllegalArgumentException(
                    "Java export requires decompileJobs between 1 and 12");
        }

        TaskMonitor monitor = taskMonitor == null ? TaskMonitor.DUMMY : taskMonitor;
        Consumer<String> output = progress == null ? unused -> { } : progress;
        long totalStarted = System.nanoTime();

        stage(monitor, output, "TurboHeader export: scanning classes and functions...");
        long scanStarted = System.nanoTime();
        var plan = Il2CppExportPlanner.plan(program, request, monitor);
        long scanNanos = System.nanoTime() - scanStarted;
        output.accept(String.format(Locale.ROOT,
                "TurboHeader plan: discovered=%d, selected=%d, scanned=%d, " +
                "matched=%d, unmatched=%d, ambiguous=%d.",
                plan.discoveredClasses(), plan.classes().size(), plan.scannedFunctions(),
                plan.matchedFunctions(), plan.unmatchedClasses().size(),
                plan.ambiguities().size()));

        stage(monitor, output, "TurboHeader export: running IL2CPP analysis...");
        var before = Il2CppExportAnalysisService.analyzeBeforePreparation(
                program, request.noreturnSeeds(), monitor);
        String noreturnSource = before.noreturn()
                .map(Il2CppNoreturnAnalyzer.AnalysisStats::source)
                .orElse("ghidra-discovered");
        output.accept(String.format(Locale.ROOT,
                "TurboHeader analysis: noreturn=%s, global=%d, runtime-metadata=%s.",
                noreturnSource, before.globalAnalyzers().size(),
                before.runtimeMetadata().outcome()));

        stage(monitor, output, String.format(Locale.ROOT,
                "TurboHeader export: preparing %d matched functions...",
                plan.matchedFunctions()));
        var preparation = Il2CppFunctionPreparationService.prepare(program, plan, monitor);
        output.accept(String.format(Locale.ROOT,
                "TurboHeader preparation: unique=%d, ready=%d, failed=%d, total=%.3fs.",
                preparation.uniqueFunctions(), preparation.preparedFunctions(),
                preparation.failedFunctions(), preparation.elapsedSeconds()));

        stage(monitor, output, "TurboHeader export: proving runtime helpers...");
        var after = Il2CppExportAnalysisService.analyzeAfterPreparation(
                program, preparation, monitor);
        long analysisNanos = before.elapsedNanos() + after.elapsedNanos();
        output.accept(String.format(Locale.ROOT,
                "TurboHeader helpers: candidates=%d, proven=%d, renamed=%d, typed=%d, " +
                "total=%.3fs.",
                after.helpers().compilerCandidates(), after.helpers().provenHelpers(),
                after.helpers().renamed(), after.helpers().typed(), after.elapsedSeconds()));

        if (program.getModificationNumber() != after.stableModificationNumber()) {
            throw new IllegalStateException("program changed after the analysis barrier");
        }
        stage(monitor, output, String.format(Locale.ROOT,
                "TurboHeader export: decompiling %d functions with %d workers...",
                preparation.preparedFunctions(), request.decompileJobs()));
        long decompileStarted = System.nanoTime();
        var decompilation = Il2CppDecompilationCoordinator.decompile(
                program, preparation, request.decompileJobs(), monitor);
        long decompilationNanos = System.nanoTime() - decompileStarted;
        if (program.getModificationNumber() != after.stableModificationNumber()) {
            throw new IllegalStateException("decompilation changed the stable Ghidra program");
        }
        output.accept(decompilationSummary(decompilation, decompilationNanos));

        stage(monitor, output, "TurboHeader export: writing C++ files and reports...");
        long elapsedBeforeWriting = System.nanoTime() - totalStarted;
        var timings = new Il2CppExportWriter.PhaseTimings(
                scanNanos, analysisNanos, preparation.elapsedNanos(),
                decompilationNanos, elapsedBeforeWriting);
        var writing = Il2CppExportWriter.write(
                program, plan, decompilation, timings, monitor);
        long totalNanos = System.nanoTime() - totalStarted;
        output.accept(String.format(Locale.ROOT,
                "TurboHeader phase timing: scan=%.3fs, analysis=%.3fs, prepare=%.3fs, " +
                "decompile=%.3fs, writes=%.3fs, total=%.3fs.",
                seconds(scanNanos), seconds(analysisNanos), preparation.elapsedSeconds(),
                seconds(decompilationNanos), seconds(writing.classWritingNanos()),
                seconds(totalNanos)));
        output.accept(String.format(Locale.ROOT,
                "TurboHeader export complete: classes=%d, functions=%d, failed=%d.",
                writing.classFiles(), writing.completedFunctions(), writing.failedFunctions()));

        return new PipelineResult(plan, before, preparation, after, decompilation,
                writing, scanNanos, analysisNanos, decompilationNanos, totalNanos);
    }

    private static String decompilationSummary(
            Il2CppDecompilationCoordinator.DecompilationResult result,
            long elapsedNanos) {
        int workers = result.batch().map(
                Il2CppDecompilerService.BatchResult::getWorkerCount).orElse(0);
        int retries = result.batch().map(
                Il2CppDecompilerService.BatchResult::getRetryCount).orElse(0);
        int recovered = result.batch().map(
                Il2CppDecompilerService.BatchResult::getRecoveredCount).orElse(0);
        return String.format(Locale.ROOT,
                "TurboHeader decompilation: workers=%d, completed=%d, failed=%d, " +
                "retries=%d, recovered=%d, total=%.3fs.",
                workers, result.completedFunctions(), result.failedFunctions(),
                retries, recovered, seconds(elapsedNanos));
    }

    private static void stage(TaskMonitor monitor, Consumer<String> progress, String message) {
        monitor.setMessage(message);
        progress.accept(message);
    }

    private static double seconds(long nanos) {
        return nanos / 1_000_000_000.0;
    }

    public record PipelineResult(
            Il2CppExportPlanner.ExportPlan plan,
            Il2CppExportAnalysisService.BeforePreparationResult beforePreparation,
            Il2CppFunctionPreparationService.PreparationResult preparation,
            Il2CppExportAnalysisService.AfterPreparationResult afterPreparation,
            Il2CppDecompilationCoordinator.DecompilationResult decompilation,
            Il2CppExportWriter.WriteResult writing,
            long scanNanos, long analysisNanos, long decompilationNanos,
            long totalNanos) {
        public PipelineResult {
            Objects.requireNonNull(plan, "plan");
            Objects.requireNonNull(beforePreparation, "beforePreparation");
            Objects.requireNonNull(preparation, "preparation");
            Objects.requireNonNull(afterPreparation, "afterPreparation");
            Objects.requireNonNull(decompilation, "decompilation");
            Objects.requireNonNull(writing, "writing");
            if (scanNanos < 0 || analysisNanos < 0 || decompilationNanos < 0 ||
                    totalNanos < 0) {
                throw new IllegalArgumentException("pipeline timings must not be negative");
            }
        }

        public double totalSeconds() {
            return totalNanos / 1_000_000_000.0;
        }
    }
}
