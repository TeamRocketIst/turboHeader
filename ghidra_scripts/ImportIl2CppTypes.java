// Imports IL2CPP Dumper C structures into the current Ghidra program using a native parser.
// @category Data Types

import java.io.File;
import java.nio.file.Path;

import ghidra.app.script.GhidraScript;
import turboheader.il2cpp.GhidraTypeImporter;
import turboheader.il2cpp.ImportDiagnostics;
import turboheader.il2cpp.NativeParser;
import turboheader.il2cpp.TypeModel;

public class ImportIl2CppTypes extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("Open a program before running this importer.");
            return;
        }

        String[] args = getScriptArgs();
        if (args.length > 4) {
            throw new IllegalArgumentException(
                    "Expected: il2cpp.h [type_offsets.json|dump.cs|-] " +
                    "[script.json|-] [allow-inferred|require-external-offsets|" +
                    "require-authoritative]");
        }
        Path header;
        Path offsets = null;
        Path script = null;
        int pointerSize = currentProgram.getDefaultPointerSize();
        var layoutPolicy = turboheader.il2cpp.GhidraTypeImporter.LayoutPolicy.ALLOW_INFERRED;

        if (args.length > 0) {
            header = Path.of(args[0]);
            if (args.length > 1 && !args[1].isBlank() && !args[1].equals("-")) {
                offsets = Path.of(args[1]);
            }
            if (args.length > 2 && !args[2].isBlank() && !args[2].equals("-")) {
                script = Path.of(args[2]);
            }
            if (args.length > 3) {
                layoutPolicy = switch (args[3]) {
                    case "allow-inferred" ->
                        turboheader.il2cpp.GhidraTypeImporter.LayoutPolicy.ALLOW_INFERRED;
                    case "require-external-offsets" ->
                        turboheader.il2cpp.GhidraTypeImporter.LayoutPolicy.REQUIRE_EXTERNAL_OFFSETS;
                    case "require-authoritative" ->
                        turboheader.il2cpp.GhidraTypeImporter.LayoutPolicy.REQUIRE_AUTHORITATIVE;
                    default -> throw new IllegalArgumentException(
                            "Unknown layout policy: " + args[3]);
                };
            }
        }
        else {
            File selectedHeader = askFile("Select IL2CPP Dumper header", "Import");
            header = selectedHeader.toPath();
            if (askYesNo("IL2CPP field offsets",
                    "Use type_offsets.json or dump.cs for external field offsets?")) {
                offsets = askFile("Select type_offsets.json or dump.cs", "Import").toPath();
            }
            else if (!askYesNo("Inferred IL2CPP layout",
                    "No offset sidecar was selected. Continue with offsets inferred from il2cpp.h? " +
                    "They are not guaranteed to match the runtime layout.")) {
                return;
            }
            if (askYesNo("IL2CPP method signatures",
                    "Apply names and prototypes from script.json?")) {
                script = askFile("Select script.json", "Import").toPath();
            }
        }

        if (pointerSize != 4 && pointerSize != 8) {
            throw new IllegalArgumentException("Program pointer size must be 4 or 8, got " + pointerSize);
        }

        System.out.println("TurboHeader: parsing IL2CPP header...");
        long parseStart = System.nanoTime();
        int nativeApi = NativeParser.nativeApiVersion();
        TypeModel.Model model = NativeParser.parse(header, offsets, pointerSize);
        double parseSeconds = (System.nanoTime() - parseStart) / 1_000_000_000.0;

        long parsedFields = model.structures().stream().mapToLong(s -> s.fields().size()).sum();
        System.out.println(String.format("TurboHeader: importing %,d structures and %,d fields...",
                model.structures().size(), parsedFields));
        GhidraTypeImporter importer = new GhidraTypeImporter(currentProgram, model, monitor,
                layoutPolicy);
        GhidraTypeImporter.ImportStats stats = importer.importTypes();
        for (GhidraTypeImporter.ImportDiagnostic diagnostic : stats.diagnostics()) {
            printerr(String.format("TurboHeader: %s.%s at 0x%x: %s",
                    diagnostic.structure(), diagnostic.field(), diagnostic.offset(),
                    diagnostic.reason()));
        }
        println(String.format(
                "TurboHeader native API %d: parsed %,d structures in %.3f s; imported %,d fields into %,d types in %.3f s " +
                "(%,d overlap unions, %,d fallbacks, %,d missing offsets).",
                nativeApi, model.structures().size(), parseSeconds, stats.fields(), stats.structures(),
                stats.elapsedSeconds(), stats.overlapUnions(), stats.fallbackFields(),
                stats.missingOffsets()));
        var evidence = stats.evidenceCounts();
        println(String.format(
                "TurboHeader layout evidence: source=%s schema=%d; %,d sidecar-copied, %,d ABI-defined, " +
                "%,d header-inferred, %,d legacy-unknown imported offsets.",
                model.offsetSource(), model.offsetSchemaVersion(), evidence.sidecarCopied(),
                evidence.abiDefined(), evidence.headerInferred(), evidence.legacyUnknown()));
        var extents = stats.lengthEvidenceCounts();
        println(String.format(
                "TurboHeader extent evidence: %,d sidecar-copied, %,d ABI-defined, " +
                "%,d header-inferred, %,d legacy-unknown structure lengths.",
                extents.sidecarCopied(), extents.abiDefined(), extents.headerInferred(),
                extents.legacyUnknown()));
        if (evidence.headerInferred() > 0) {
            printerr(String.format(
                    "TurboHeader warning: %,d field offsets were inferred from il2cpp.h and are not " +
                    "runtime-authoritative.", evidence.headerInferred()));
        }
        if (extents.headerInferred() > 0) {
            printerr(ImportDiagnostics.inferredExtentWarning(extents.headerInferred()));
        }
        if (model.missingOffsets() > 0) {
            TypeModel.MissingOffsetReasons reasons = model.missingOffsetReasons();
            println(String.format(
                    "TurboHeader missing offsets: %,d open generic, %,d concrete sidecar absent, " +
                    "%,d unresolved generic parent, %,d object-header offset, %,d unsupported layout" +
                    (reasons.legacyUnclassified() > 0 ? ", %,d legacy unclassified." : "."),
                    reasons.openGenericDefinition(), reasons.concreteInstanceAbsent(),
                    reasons.unresolvedGenericParent(), reasons.objectHeaderOffset(),
                    reasons.unsupportedLayout(), reasons.legacyUnclassified()));
        }

        if (script != null) {
            System.out.println("TurboHeader: reading script metadata...");
            var scriptData = turboheader.il2cpp.ScriptMethodReader.readAll(script);
            System.out.println(String.format(
                    "TurboHeader script: %,d strings, %,d metadata slots, %,d method slots, %,d methods.",
                    scriptData.strings().size(), scriptData.metadata().size(),
                    scriptData.metadataMethods().size(), scriptData.methods().size()));
            var stringResult = new turboheader.il2cpp.GhidraStringImporter(currentProgram, monitor)
                    .importStrings(scriptData.strings());
            var stringStats = stringResult.stats();
            println(String.format(
                    "TurboHeader strings: %,d read, %,d labels created, %,d labels reused, " +
                    "%,d comments created, %,d globals typed, %,d primary labels changed, " +
                    "%,d failed in %.3f s.",
                    stringStats.total(), stringStats.labelsCreated(), stringStats.labelsReused(),
                    stringStats.commentsCreated(), stringStats.typed(),
                    stringStats.primaryLabelsChanged(),
                    stringStats.failed(), stringStats.elapsedSeconds()));
            for (var failure : stringStats.failureCounts().entrySet()) {
                printerr(String.format("TurboHeader strings: %,d %s", failure.getValue(),
                        failure.getKey()));
            }
            for (String sample : stringStats.failureSamples()) {
                printerr("TurboHeader string sample: " + sample);
            }

            var metadataResult = new turboheader.il2cpp.GhidraMetadataImporter(currentProgram, monitor)
                    .importMetadata(scriptData.metadata());
            var metadataStats = metadataResult.stats();
            println(String.format(
                    "TurboHeader metadata: %,d read, %,d labels created, %,d globals typed, " +
                    "%,d failed in %.3f s.",
                    metadataStats.total(), metadataStats.labelsCreated(), metadataStats.typed(),
                    metadataStats.failed(), metadataStats.elapsedSeconds()));
            for (var failure : metadataStats.failureCounts().entrySet()) {
                printerr(String.format("TurboHeader metadata: %,d %s", failure.getValue(),
                        failure.getKey()));
            }
            for (String sample : metadataStats.failureSamples()) {
                printerr("TurboHeader metadata sample: " + sample);
            }

            var methodMetadataResult =
                    new turboheader.il2cpp.GhidraMethodMetadataImporter(currentProgram, monitor)
                            .importMethods(scriptData.metadataMethods());
            var methodMetadataStats = methodMetadataResult.stats();
            println(String.format(
                    "TurboHeader method metadata: %,d read, %,d labels created, %,d reused, " +
                    "%,d comments created, %,d globals typed, %,d failed in %.3f s.",
                    methodMetadataStats.total(), methodMetadataStats.labelsCreated(),
                    methodMetadataStats.labelsReused(), methodMetadataStats.commentsCreated(),
                    methodMetadataStats.typed(), methodMetadataStats.failed(),
                    methodMetadataStats.elapsedSeconds()));
            for (var failure : methodMetadataStats.failureCounts().entrySet()) {
                printerr(String.format("TurboHeader method metadata: %,d %s",
                        failure.getValue(), failure.getKey()));
            }
            for (String sample : methodMetadataStats.failureSamples()) {
                printerr("TurboHeader method metadata sample: " + sample);
            }

            var relocationTargets = new java.util.HashMap<>(
                    metadataResult.relocationTargets());
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
            var relocationStats = new turboheader.il2cpp.GhidraRelocationImporter(
                    currentProgram, monitor).importRelocations(relocationTargets);
            println(String.format(
                    "TurboHeader relocations: %,d scanned once, %,d matched, %,d slots typed, " +
                    "%,d string labels created, %,d reused, %,d comments created, " +
                    "%,d method labels created, %,d reused, %,d comments created, " +
                    "%,d failed in %.3f s.",
                    relocationStats.relocationsScanned(), relocationStats.slotsMatched(),
                    relocationStats.slotsTyped(), relocationStats.stringLabelsCreated(),
                    relocationStats.stringLabelsReused(),
                    relocationStats.stringCommentsCreated(),
                    relocationStats.methodLabelsCreated(),
                    relocationStats.methodLabelsReused(),
                    relocationStats.methodCommentsCreated(), relocationStats.failed(),
                    relocationStats.elapsedSeconds()));
            for (var failure : relocationStats.failureCounts().entrySet()) {
                printerr(String.format("TurboHeader relocations: %,d %s", failure.getValue(),
                        failure.getKey()));
            }
            for (String sample : relocationStats.failureSamples()) {
                printerr("TurboHeader relocation sample: " + sample);
            }

            var methods = scriptData.methods();
            var methodStats = new turboheader.il2cpp.GhidraMethodImporter(currentProgram, monitor)
                    .importMethods(methods);
            println(String.format(
                    "TurboHeader methods: %,d read, %,d applied, %,d functions created, %,d failed in %.3f s " +
                    "(%,d duplicate names repaired, %,d specialized MethodInfo pointers canonicalized, " +
                    "%,d opaque pointer types, %,d assembly identities).",
                    methodStats.total(), methodStats.applied(), methodStats.functionsCreated(),
                    methodStats.failed(), methodStats.elapsedSeconds(),
                    methodStats.duplicateNamesRepaired(), methodStats.specializedMethodInfoPointers(),
                    methodStats.opaquePointerTypes(), methodStats.assemblyIdentities()));
            for (var failure : methodStats.failureCounts().entrySet()) {
                printerr(String.format("TurboHeader methods: %,d %s", failure.getValue(), failure.getKey()));
            }
            for (String sample : methodStats.failureSamples()) {
                printerr("TurboHeader method sample: " + sample);
            }
            if (stringStats.failed() != 0 || metadataStats.failed() != 0 ||
                    methodMetadataStats.failed() != 0 ||
                    relocationStats.failed() != 0 ||
                    methodStats.failed() != 0) {
                throw new IllegalStateException(String.format(
                        "TurboHeader did not apply %,d of %,d strings, %,d of %,d metadata slots, " +
                        "%,d of %,d method metadata entries, %,d relocation slots, and %,d of %,d " +
                        "method signatures",
                        stringStats.failed(), stringStats.total(),
                        metadataStats.failed(), metadataStats.total(),
                        methodMetadataStats.failed(), methodMetadataStats.total(),
                        relocationStats.failed(),
                        methodStats.failed(), methodStats.total()));
            }
        }
    }
}
