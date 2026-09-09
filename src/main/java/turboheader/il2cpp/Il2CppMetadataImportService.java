package turboheader.il2cpp;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/** Imports script.json annotations and managed method signatures into a program. */
public final class Il2CppMetadataImportService {
    private final Program program;
    private final TaskMonitor monitor;
    private final Consumer<String> output;
    private final Consumer<String> errors;

    public Il2CppMetadataImportService(Program program, TaskMonitor monitor,
            Consumer<String> output, Consumer<String> errors) {
        this.program = Objects.requireNonNull(program, "program");
        this.monitor = monitor == null ? TaskMonitor.DUMMY : monitor;
        this.output = Objects.requireNonNull(output, "output");
        this.errors = Objects.requireNonNull(errors, "errors");
    }

    public void importScript(Path script) throws Exception {
        output.accept("TurboHeader: reading script metadata...");
        var scriptData = ScriptMethodReader.readAll(script);
        output.accept(String.format(
                "TurboHeader script: %,d strings, %,d metadata slots, %,d method slots, %,d methods.",
                scriptData.strings().size(), scriptData.metadata().size(),
                scriptData.metadataMethods().size(), scriptData.methods().size()));

        var stringResult = new GhidraStringImporter(program, monitor)
                .importStrings(scriptData.strings());
        var stringStats = stringResult.stats();
        output.accept(String.format(
                "TurboHeader strings: %,d read, %,d labels created, %,d labels reused, " +
                "%,d comments created, %,d globals typed, %,d primary labels changed, " +
                "%,d failed in %.3f s.",
                stringStats.total(), stringStats.labelsCreated(), stringStats.labelsReused(),
                stringStats.commentsCreated(), stringStats.typed(),
                stringStats.primaryLabelsChanged(), stringStats.failed(),
                stringStats.elapsedSeconds()));
        reportFailures("TurboHeader strings", "TurboHeader string sample",
                stringStats.failureCounts(), stringStats.failureSamples());

        var metadataResult = new GhidraMetadataImporter(program, monitor)
                .importMetadata(scriptData.metadata());
        var metadataStats = metadataResult.stats();
        output.accept(String.format(
                "TurboHeader metadata: %,d read, %,d labels created, %,d globals typed, " +
                "%,d failed in %.3f s.",
                metadataStats.total(), metadataStats.labelsCreated(), metadataStats.typed(),
                metadataStats.failed(), metadataStats.elapsedSeconds()));
        reportFailures("TurboHeader metadata", "TurboHeader metadata sample",
                metadataStats.failureCounts(), metadataStats.failureSamples());

        var methodMetadataResult = new GhidraMethodMetadataImporter(program, monitor)
                .importMethods(scriptData.metadataMethods());
        var methodMetadataStats = methodMetadataResult.stats();
        output.accept(String.format(
                "TurboHeader method metadata: %,d read, %,d labels created, %,d reused, " +
                "%,d comments created, %,d globals typed, %,d failed in %.3f s.",
                methodMetadataStats.total(), methodMetadataStats.labelsCreated(),
                methodMetadataStats.labelsReused(), methodMetadataStats.commentsCreated(),
                methodMetadataStats.typed(), methodMetadataStats.failed(),
                methodMetadataStats.elapsedSeconds()));
        reportFailures("TurboHeader method metadata", "TurboHeader method metadata sample",
                methodMetadataStats.failureCounts(), methodMetadataStats.failureSamples());

        var relocationTargets = new HashMap<>(metadataResult.relocationTargets());
        for (var target : stringResult.relocationTargets().entrySet()) {
            if (relocationTargets.put(target.getKey(), target.getValue()) != null) {
                throw new IllegalStateException(
                        "ScriptString and ScriptMetadata share address " + target.getKey());
            }
        }
        for (var target : methodMetadataResult.relocationTargets().entrySet()) {
            if (relocationTargets.put(target.getKey(), target.getValue()) != null) {
                throw new IllegalStateException(
                        "ScriptMetadataMethod shares address " + target.getKey());
            }
        }

        var relocationStats = new GhidraRelocationImporter(program, monitor)
                .importRelocations(relocationTargets);
        output.accept(String.format(
                "TurboHeader relocations: %,d scanned once, %,d matched, %,d slots typed, " +
                "%,d string labels created, %,d reused, %,d comments created, " +
                "%,d method labels created, %,d reused, %,d comments created, " +
                "%,d failed in %.3f s.",
                relocationStats.relocationsScanned(), relocationStats.slotsMatched(),
                relocationStats.slotsTyped(), relocationStats.stringLabelsCreated(),
                relocationStats.stringLabelsReused(), relocationStats.stringCommentsCreated(),
                relocationStats.methodLabelsCreated(), relocationStats.methodLabelsReused(),
                relocationStats.methodCommentsCreated(), relocationStats.failed(),
                relocationStats.elapsedSeconds()));
        reportFailures("TurboHeader relocations", "TurboHeader relocation sample",
                relocationStats.failureCounts(), relocationStats.failureSamples());

        var methodStats = new GhidraMethodImporter(program, monitor)
                .importMethods(scriptData.methods());
        output.accept(String.format(
                "TurboHeader methods: %,d read, %,d applied, %,d functions created, %,d failed in %.3f s " +
                "(%,d duplicate names repaired, %,d specialized MethodInfo pointers canonicalized, " +
                "%,d opaque pointer types, %,d assembly identities).",
                methodStats.total(), methodStats.applied(), methodStats.functionsCreated(),
                methodStats.failed(), methodStats.elapsedSeconds(),
                methodStats.duplicateNamesRepaired(), methodStats.specializedMethodInfoPointers(),
                methodStats.opaquePointerTypes(), methodStats.assemblyIdentities()));
        reportFailures("TurboHeader methods", "TurboHeader method sample",
                methodStats.failureCounts(), methodStats.failureSamples());

        if (stringStats.failed() != 0 || metadataStats.failed() != 0 ||
                methodMetadataStats.failed() != 0 || relocationStats.failed() != 0 ||
                methodStats.failed() != 0) {
            throw new IllegalStateException(String.format(
                    "TurboHeader did not apply %,d of %,d strings, %,d of %,d metadata slots, " +
                    "%,d of %,d method metadata entries, %,d relocation slots, and %,d of %,d " +
                    "method signatures",
                    stringStats.failed(), stringStats.total(),
                    metadataStats.failed(), metadataStats.total(),
                    methodMetadataStats.failed(), methodMetadataStats.total(),
                    relocationStats.failed(), methodStats.failed(), methodStats.total()));
        }
    }

    private void reportFailures(String countPrefix, String samplePrefix,
            Map<String, Integer> counts, List<String> samples) {
        for (var failure : counts.entrySet()) {
            errors.accept(String.format("%s: %,d %s", countPrefix, failure.getValue(),
                    failure.getKey()));
        }
        for (String sample : samples) {
            errors.accept(samplePrefix + ": " + sample);
        }
    }
}
