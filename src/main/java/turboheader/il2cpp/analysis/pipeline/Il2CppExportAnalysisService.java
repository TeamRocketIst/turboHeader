package turboheader.il2cpp.analysis.pipeline;

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
import turboheader.il2cpp.decompile.Il2CppDecompilationPolicy;
import turboheader.il2cpp.analysis.delegatecall.Il2CppDelegateCallAnalyzer;
import turboheader.il2cpp.analysis.delegatecall.Il2CppDelegateCallPublisher;
import turboheader.il2cpp.analysis.delegatecall.Il2CppDelegatePrototypeCatalog;
import turboheader.il2cpp.analysis.interfacecall.Il2CppInterfaceCallAnalyzer;
import turboheader.il2cpp.analysis.interfacecall.Il2CppInterfaceCallPublisher;
import turboheader.il2cpp.analysis.helpers.Il2CppExportedHelperAnalyzer;
import turboheader.il2cpp.analysis.helpers.Il2CppRuntimeMetadataAnalyzer;
import turboheader.il2cpp.analysis.noreturn.Il2CppNoreturnAnalyzer;
import turboheader.il2cpp.analysis.sharedgeneric.Il2CppSharedGenericCallAnalyzer;
import turboheader.il2cpp.analysis.sharedgeneric.Il2CppSharedGenericCallPublisher;
import turboheader.il2cpp.metadata.Il2CppSharedGenericCallStore;
import turboheader.il2cpp.metadata.Il2CppReferenceGenericCallStore;

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
        return analyzeAfterPreparation(program, preparation, 1, taskMonitor);
    }

    public static AfterPreparationResult analyzeAfterPreparation(Program program,
            Il2CppFunctionPreparationService.PreparationResult preparation,
            int decompileJobs, TaskMonitor taskMonitor) throws Exception {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(preparation, "preparation");
        int delegateWorkers = Il2CppDecompilationPolicy.delegateWorkers(decompileJobs);
        TaskMonitor monitor = taskMonitor == null ? TaskMonitor.DUMMY : taskMonitor;
        long started = System.nanoTime();

        List<Function> functions = new ArrayList<>();
        for (var outcome : preparation.addressOrder()) {
            monitor.checkCancelled();
            if (outcome instanceof Il2CppFunctionPreparationService.PreparedFunction ready) {
                functions.add(ready.decompileFunction());
            }
        }

        var delegatePrototypes = Il2CppDelegatePrototypeCatalog.read(program);
        monitor.checkCancelled();
        var helpers = new Il2CppExportedHelperAnalyzer(program, functions, monitor).analyze();
        monitor.checkCancelled();
        var interfaceCalls = Il2CppInterfaceCallAnalyzer.analyze(
                program, functions, helpers.anchors(), monitor);
        monitor.checkCancelled();
        var sharedGenericCatalog = Il2CppSharedGenericCallStore.read(program);
        var referenceGenericCatalog = Il2CppReferenceGenericCallStore.read(program);
        var sharedGenericCalls = Il2CppSharedGenericCallAnalyzer.analyze(program, functions,
                sharedGenericCatalog, referenceGenericCatalog, monitor);
        monitor.checkCancelled();
        // Delegate receivers can come from shared-generic result buffers.
        var publishedSharedGenericCalls = Il2CppSharedGenericCallPublisher.publish(
                program, sharedGenericCalls.proofs(), monitor);
        monitor.checkCancelled();
        var delegateCalls = Il2CppDelegateCallAnalyzer.analyze(
                program, functions, delegatePrototypes, delegateWorkers, monitor);
        monitor.checkCancelled();
        var publishedInterfaceCalls = Il2CppInterfaceCallPublisher.publish(
                program, interfaceCalls.proofs(), monitor);
        monitor.checkCancelled();
        var publishedDelegateCalls = Il2CppDelegateCallPublisher.publish(
                program, delegateCalls.proofs(), monitor);
        monitor.checkCancelled();
        return new AfterPreparationResult(helpers, delegatePrototypes,
                interfaceCalls, delegateCalls, publishedInterfaceCalls,
                publishedDelegateCalls, sharedGenericCalls,
                publishedSharedGenericCalls,
                program.getModificationNumber(),
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
            Optional<Il2CppDelegatePrototypeCatalog> delegatePrototypes,
            Il2CppInterfaceCallAnalyzer.AnalysisStats interfaceCalls,
            Il2CppDelegateCallAnalyzer.AnalysisStats delegateCalls,
            Il2CppInterfaceCallPublisher.PublicationStats publishedInterfaceCalls,
            Il2CppDelegateCallPublisher.PublicationStats publishedDelegateCalls,
            Il2CppSharedGenericCallAnalyzer.AnalysisStats sharedGenericCalls,
            Il2CppSharedGenericCallPublisher.PublicationStats publishedSharedGenericCalls,
            long stableModificationNumber, long elapsedNanos) {
        public AfterPreparationResult {
            Objects.requireNonNull(helpers, "helpers");
            Objects.requireNonNull(delegatePrototypes, "delegatePrototypes");
            Objects.requireNonNull(interfaceCalls, "interfaceCalls");
            Objects.requireNonNull(delegateCalls, "delegateCalls");
            Objects.requireNonNull(publishedInterfaceCalls, "publishedInterfaceCalls");
            Objects.requireNonNull(publishedDelegateCalls, "publishedDelegateCalls");
            Objects.requireNonNull(sharedGenericCalls, "sharedGenericCalls");
            Objects.requireNonNull(publishedSharedGenericCalls,
                    "publishedSharedGenericCalls");
            if (stableModificationNumber < 0 || elapsedNanos < 0) {
                throw new IllegalArgumentException("analysis statistics must not be negative");
            }
        }

        public double elapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }
}
