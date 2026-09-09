// Imports IL2CPP Dumper C structures into the current Ghidra program using a native parser.
// @category Data Types

import java.io.File;
import java.nio.file.Path;

import ghidra.app.script.GhidraScript;
import turboheader.il2cpp.GhidraTypeImporter;
import turboheader.il2cpp.HeadlessRequestReader;
import turboheader.il2cpp.Il2CppMetadataImportService;
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
        boolean requestMode = args.length > 0 && args[0].equals("--request");
        if (requestMode && args.length != 2) {
            throw new IllegalArgumentException("Expected: --request <import-request.json>");
        }
        if (!requestMode && args.length > 4) {
            throw new IllegalArgumentException(
                    "Expected: il2cpp.h [type_offsets.json|dump.cs|-] " +
                    "[script.json|-] [allow-inferred|require-external-offsets|" +
                    "require-authoritative]");
        }
        Path header;
        Path offsets = null;
        Path script = null;
        int pointerSize = currentProgram.getDefaultPointerSize();
        var layoutPolicy = GhidraTypeImporter.LayoutPolicy.ALLOW_INFERRED;

        if (requestMode) {
            var request = HeadlessRequestReader.readImport(Path.of(args[1]));
            header = request.header();
            offsets = request.offsets();
            script = request.methods();
            layoutPolicy = layoutPolicy(request.layoutPolicy());
        }
        else if (args.length > 0) {
            header = Path.of(args[0]);
            if (args.length > 1 && !args[1].isBlank() && !args[1].equals("-")) {
                offsets = Path.of(args[1]);
            }
            if (args.length > 2 && !args[2].isBlank() && !args[2].equals("-")) {
                script = Path.of(args[2]);
            }
            if (args.length > 3) {
                layoutPolicy = layoutPolicy(args[3]);
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
            new Il2CppMetadataImportService(currentProgram, monitor, this::println, this::printerr)
                    .importScript(script);
        }
    }

    private static GhidraTypeImporter.LayoutPolicy layoutPolicy(String value) {
        return switch (value) {
            case "allow-inferred" -> GhidraTypeImporter.LayoutPolicy.ALLOW_INFERRED;
            case "require-external-offsets" ->
                GhidraTypeImporter.LayoutPolicy.REQUIRE_EXTERNAL_OFFSETS;
            case "require-authoritative" ->
                GhidraTypeImporter.LayoutPolicy.REQUIRE_AUTHORITATIVE;
            default -> throw new IllegalArgumentException("Unknown layout policy: " + value);
        };
    }

    private static GhidraTypeImporter.LayoutPolicy layoutPolicy(
            HeadlessRequestReader.LayoutPolicy value) {
        return switch (value) {
            case ALLOW_INFERRED -> GhidraTypeImporter.LayoutPolicy.ALLOW_INFERRED;
            case REQUIRE_EXTERNAL_OFFSETS ->
                GhidraTypeImporter.LayoutPolicy.REQUIRE_EXTERNAL_OFFSETS;
            case REQUIRE_AUTHORITATIVE ->
                GhidraTypeImporter.LayoutPolicy.REQUIRE_AUTHORITATIVE;
        };
    }
}
