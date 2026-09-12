package turboheader.il2cpp;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import turboheader.il2cpp.decompile.GhidraFunctionMatcher;
import turboheader.il2cpp.decompile.Il2CppFunctionMatcher;
import turboheader.il2cpp.exporting.Il2CppClassCatalog;
import turboheader.il2cpp.exporting.Il2CppClassSelector;
import turboheader.il2cpp.exporting.Il2CppOutputPath;

public final class Il2CppExportPlanner {
    private static final List<String> PRESELECTED_ASSEMBLIES = List.of("*");

    private Il2CppExportPlanner() {
    }

    public static ExportPlan plan(Program program, HeadlessRequestReader.ExportRequest request,
            TaskMonitor taskMonitor) throws IOException, CancelledException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(request, "request");

        List<Il2CppClassCatalog.ClassEntry> discovered =
                Il2CppClassCatalog.scan(request.classSource());
        var selection = Il2CppClassSelector.select(discovered, request.scope(),
                PRESELECTED_ASSEMBLIES, List.of(), request.frameworkRules());
        if (selection.classes().isEmpty()) {
            throw new IOException("no classes matched the export request");
        }

        var matched = GhidraFunctionMatcher.match(program, selection.classes(), taskMonitor);
        List<ClassPlan> classes = new ArrayList<>(selection.classes().size());
        List<Il2CppClassCatalog.ClassEntry> unmatched = new ArrayList<>();
        Map<Il2CppClassCatalog.ClassEntry, Path> outputPaths =
                Il2CppOutputPath.forClasses(selection.classes());

        for (var entry : selection.classes()) {
            List<Function> functions = matched.functionsByClass().get(entry);
            if (functions == null) {
                throw new IllegalStateException("selected class is missing from function matches");
            }
            if (functions.isEmpty()) {
                unmatched.add(entry);
            }
            classes.add(new ClassPlan(entry, outputPaths.get(entry), functions));
        }

        return new ExportPlan(
                request,
                List.copyOf(classes),
                List.copyOf(unmatched),
                matched.ambiguities(),
                selection.assemblies(),
                discovered.size(),
                matched.scannedFunctions(),
                matched.matchedFunctions(),
                matched.assemblyAmbiguitiesResolved(),
                matched.assemblyMismatchesSkipped());
    }

    public record ClassPlan(Il2CppClassCatalog.ClassEntry classEntry, Path relativeOutput,
            List<Function> functions) {
        public ClassPlan {
            Objects.requireNonNull(classEntry, "classEntry");
            Objects.requireNonNull(relativeOutput, "relativeOutput");
            functions = List.copyOf(functions);
            if (relativeOutput.isAbsolute() ||
                    !relativeOutput.normalize().equals(relativeOutput) ||
                    relativeOutput.startsWith(Path.of("..")) ||
                    relativeOutput.getFileName() == null ||
                    relativeOutput.getFileName().toString().isEmpty()) {
                throw new IllegalArgumentException(
                        "class output path must be normalized and relative");
            }
        }
    }

    public record ExportPlan(
            HeadlessRequestReader.ExportRequest request,
            List<ClassPlan> classes,
            List<Il2CppClassCatalog.ClassEntry> unmatchedClasses,
            List<Il2CppFunctionMatcher.Ambiguity> ambiguities,
            Map<String, Il2CppClassSelector.AssemblyDecision> assemblies,
            int discoveredClasses,
            int scannedFunctions,
            int matchedFunctions,
            int assemblyAmbiguitiesResolved,
            int assemblyMismatchesSkipped) {
        public ExportPlan {
            Objects.requireNonNull(request, "request");
            classes = List.copyOf(classes);
            unmatchedClasses = List.copyOf(unmatchedClasses);
            ambiguities = List.copyOf(ambiguities);
            assemblies = Collections.unmodifiableMap(new LinkedHashMap<>(assemblies));
        }
    }
}
