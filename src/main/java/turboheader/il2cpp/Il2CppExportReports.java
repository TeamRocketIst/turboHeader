package turboheader.il2cpp;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import turboheader.il2cpp.decompile.Il2CppDecompilationCoordinator;
import turboheader.il2cpp.decompile.Il2CppDecompilerService;

final class Il2CppExportReports {
    private Il2CppExportReports() {
    }

    static ReportResult write(Il2CppOutputDirectory output, Program program,
            Il2CppExportPlanner.ExportPlan plan,
            Il2CppDecompilationCoordinator.DecompilationResult decompilation,
            Il2CppExportWriter.PhaseTimings timings, long classWritingNanos,
            long totalExportNanos, TaskMonitor monitor)
            throws IOException, CancelledException {
        long started = System.nanoTime();
        long bytes = output.write(Path.of("_export_summary.txt"),
                writer -> writeSummary(writer, program, plan, decompilation, timings,
                        classWritingNanos, totalExportNanos));
        bytes += output.write(Path.of("_assembly_filter.txt"),
                writer -> writeAssemblies(writer, plan, monitor));
        bytes += writeOptional(output, plan, monitor);
        return new ReportResult(bytes, System.nanoTime() - started);
    }

    private static void writeSummary(BufferedWriter writer, Program program,
            Il2CppExportPlanner.ExportPlan plan,
            Il2CppDecompilationCoordinator.DecompilationResult decompilation,
            Il2CppExportWriter.PhaseTimings timings, long classWritingNanos,
            long totalExportNanos) throws IOException {
        long included = plan.assemblies().values().stream()
                .filter(Il2CppClassSelector.AssemblyDecision::included).count();
        long skipped = plan.assemblies().size() - included;
        int retries = decompilation.batch().map(
                Il2CppDecompilerService.BatchResult::getRetryCount).orElse(0);
        int recovered = decompilation.batch().map(
                Il2CppDecompilerService.BatchResult::getRecoveredCount).orElse(0);

        Il2CppExportText.line(writer, "Ghidra cpp2il decompilation export summary");
        Il2CppExportText.line(writer, "Program: " +
                Il2CppExportText.singleLine(program.getName()));
        Il2CppExportText.line(writer, "Class source: cpp2il DiffableCs directory; " +
                "class names from .cs filenames");
        Il2CppExportText.line(writer, "Assembly selection mode: " + scope(plan));
        Il2CppExportText.line(writer, "Framework ignore file: " + rules(plan));
        Il2CppExportText.line(writer, "Assemblies included: " + included);
        Il2CppExportText.line(writer, "Assemblies skipped: " + skipped);
        Il2CppExportText.line(writer, "Classes selected: " + plan.classes().size());
        Il2CppExportText.line(writer,
                "Class files written: " + decompilation.classes().size());
        Il2CppExportText.line(writer, "Functions scanned: " + plan.scannedFunctions());
        Il2CppExportText.line(writer, "Functions matched/exported: " +
                decompilation.completedFunctions());
        Il2CppExportText.line(writer, "Functions failed to decompile: " +
                decompilation.failedFunctions());
        Il2CppExportText.line(writer, "Decompiler restarts: " + retries);
        Il2CppExportText.line(writer, "Functions recovered after restart: " + recovered);
        Il2CppExportText.line(writer,
                "Ambiguous functions skipped: " + plan.ambiguities().size());
        Il2CppExportText.line(writer, "Assembly ambiguities resolved: " +
                plan.assemblyAmbiguitiesResolved());
        Il2CppExportText.line(writer, "Assembly mismatches skipped: " +
                plan.assemblyMismatchesSkipped());
        Il2CppExportText.line(writer,
                "Classes with no matches: " + plan.unmatchedClasses().size());
        Il2CppExportText.line(writer,
                "Decompile topology: staged-java-jobs-" + plan.request().decompileJobs());
        timing(writer, "class scan", timings.scanNanos());
        timing(writer, "analysis", timings.analysisNanos());
        timing(writer, "function preparation", timings.preparationNanos());
        timing(writer, "decompilation", timings.decompilationNanos());
        timing(writer, "output writes", classWritingNanos);
        timing(writer, "total export", totalExportNanos);
        writer.write('\n');
        Il2CppExportText.line(writer,
                "Matching note: class names are matched at token boundaries, so " +
                "one-letter classes only match symbols whose first token/path component is " +
                "that exact letter.");
    }

    private static void writeAssemblies(BufferedWriter writer,
            Il2CppExportPlanner.ExportPlan plan, TaskMonitor monitor)
            throws IOException, CancelledException {
        Il2CppExportText.line(writer, "Assembly selection mode: " + scope(plan));
        Il2CppExportText.line(writer, "Framework ignore file: " + rules(plan));
        writer.write('\n');

        List<Il2CppClassSelector.AssemblyDecision> decisions =
                new ArrayList<>(plan.assemblies().values());
        decisions.sort(Comparator.comparing(
                decision -> decision.assembly().toLowerCase(Locale.ROOT)));
        for (var decision : decisions) {
            monitor.checkCancelled();
            Il2CppExportText.line(writer,
                    "[" + (decision.included() ? "INCLUDE" : "SKIP") + "] " +
                    Il2CppExportText.singleLine(decision.assembly()) + " -- " +
                    Il2CppExportText.singleLine(decision.reason()));
        }
    }

    private static long writeOptional(Il2CppOutputDirectory output,
            Il2CppExportPlanner.ExportPlan plan, TaskMonitor monitor)
            throws IOException, CancelledException {
        long bytes = 0;
        Path ambiguous = Path.of("_ambiguous_matches.txt");
        if (plan.ambiguities().isEmpty()) {
            output.deleteIfRegular(ambiguous);
        }
        else {
            bytes += output.write(ambiguous, writer -> {
                for (var item : plan.ambiguities()) {
                    monitor.checkCancelled();
                    Il2CppExportText.line(writer,
                            "Function: " + Il2CppExportText.singleLine(item.functionName()));
                    Il2CppExportText.line(writer,
                            "Matched key: " + Il2CppExportText.singleLine(item.candidate()));
                    Il2CppExportText.line(writer, "Candidate classes:");
                    for (String name : item.classes()) {
                        Il2CppExportText.line(writer,
                                "  - " + Il2CppExportText.singleLine(name));
                    }
                    writer.write('\n');
                }
            });
        }

        Path unmatched = Path.of("_classes_with_no_matches.txt");
        if (plan.unmatchedClasses().isEmpty()) {
            output.deleteIfRegular(unmatched);
        }
        else {
            bytes += output.write(unmatched, writer -> {
                for (var entry : plan.unmatchedClasses()) {
                    monitor.checkCancelled();
                    Il2CppExportText.line(writer,
                            Il2CppExportText.singleLine(entry.displayName()));
                }
            });
        }
        return bytes;
    }

    private static void timing(BufferedWriter writer, String phase, long nanos)
            throws IOException {
        Il2CppExportText.line(writer, String.format(Locale.ROOT,
                "Timing %s seconds: %.6f", phase, nanos / 1_000_000_000.0));
    }

    private static String scope(Il2CppExportPlanner.ExportPlan plan) {
        return plan.request().scope().name().toLowerCase(Locale.ROOT);
    }

    private static String rules(Il2CppExportPlanner.ExportPlan plan) {
        return plan.request().frameworkRules() == null
                ? "<built-in defaults only>" : "<configured>";
    }

    record ReportResult(long bytesWritten, long elapsedNanos) {
    }
}
