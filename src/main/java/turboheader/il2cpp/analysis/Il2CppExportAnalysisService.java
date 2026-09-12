package turboheader.il2cpp.analysis;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import ghidra.app.services.Analyzer;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import turboheader.il2cpp.decompile.Il2CppFunctionPreparationService;

public final class Il2CppExportAnalysisService {
    private static final List<String> GLOBAL_ANALYZERS = List.of(
            "AARCH64 ELF PLT Thunks");

    private Il2CppExportAnalysisService() {
    }

    public static BeforePreparationResult analyzeBeforePreparation(Program program,
            Path noreturnSeeds, TaskMonitor taskMonitor) throws Exception {
        Objects.requireNonNull(program, "program");
        TaskMonitor monitor = taskMonitor == null ? TaskMonitor.DUMMY : taskMonitor;
        long started = System.nanoTime();

        var profile = Il2CppAnalysisProfile.apply(program, noreturnSeeds);
        monitor.checkCancelled();
        List<String> globalAnalyzers = runGlobalAnalyzers(program, monitor);
        monitor.checkCancelled();

        Optional<Il2CppNoreturnAnalyzer.AnalysisStats> noreturn = Optional.empty();
        if (profile.customNoreturn()) {
            String seedPath = noreturnSeeds == null ? "" : noreturnSeeds.toString();
            noreturn = Optional.of(Il2CppNoreturnAnalyzer.analyze(program, seedPath, monitor));
        }
        monitor.checkCancelled();
        var runtimeMetadata = Il2CppRuntimeMetadataAnalyzer.analyze(program, monitor);
        monitor.checkCancelled();

        return new BeforePreparationResult(profile, globalAnalyzers, noreturn,
                runtimeMetadata, System.nanoTime() - started);
    }

    public static AfterPreparationResult analyzeAfterPreparation(Program program,
            Il2CppFunctionPreparationService.PreparationResult preparation,
            TaskMonitor taskMonitor) throws Exception {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(preparation, "preparation");
        TaskMonitor monitor = taskMonitor == null ? TaskMonitor.DUMMY : taskMonitor;
        long started = System.nanoTime();

        List<Function> functions = new ArrayList<>();
        for (var outcome : preparation.addressOrder()) {
            monitor.checkCancelled();
            if (outcome instanceof Il2CppFunctionPreparationService.PreparedFunction ready) {
                functions.add(ready.decompileFunction());
            }
        }

        var helpers = new Il2CppExportedHelperAnalyzer(program, functions, monitor).analyze();
        monitor.checkCancelled();
        return new AfterPreparationResult(helpers, program.getModificationNumber(),
                System.nanoTime() - started);
    }

    private static List<String> runGlobalAnalyzers(Program program, TaskMonitor monitor)
            throws CancelledException {
        AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
        List<String> scheduled = new ArrayList<>();
        for (String name : GLOBAL_ANALYZERS) {
            monitor.checkCancelled();
            Analyzer analyzer = manager.getAnalyzer(name);
            if (analyzer == null || !analyzer.canAnalyze(program)) {
                continue;
            }
            manager.scheduleOneTimeAnalysis(analyzer, program.getMemory());
            scheduled.add(name);
        }
        if (!scheduled.isEmpty()) {
            manager.startAnalysis(monitor, true);
        }
        return List.copyOf(scheduled);
    }

    public record BeforePreparationResult(
            Il2CppAnalysisProfile.ProfileResult profile,
            List<String> globalAnalyzers,
            Optional<Il2CppNoreturnAnalyzer.AnalysisStats> noreturn,
            Il2CppRuntimeMetadataAnalyzer.AnalysisStats runtimeMetadata,
            long elapsedNanos) {
        public BeforePreparationResult {
            Objects.requireNonNull(profile, "profile");
            globalAnalyzers = List.copyOf(globalAnalyzers);
            Objects.requireNonNull(noreturn, "noreturn");
            Objects.requireNonNull(runtimeMetadata, "runtimeMetadata");
            if (elapsedNanos < 0) {
                throw new IllegalArgumentException("elapsedNanos must not be negative");
            }
        }

        public double elapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }

    public record AfterPreparationResult(
            Il2CppExportedHelperAnalyzer.AnalysisStats helpers,
            long stableModificationNumber, long elapsedNanos) {
        public AfterPreparationResult {
            Objects.requireNonNull(helpers, "helpers");
            if (stableModificationNumber < 0 || elapsedNanos < 0) {
                throw new IllegalArgumentException("analysis statistics must not be negative");
            }
        }

        public double elapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }
}
