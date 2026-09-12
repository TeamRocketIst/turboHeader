package turboheader.il2cpp;

import java.nio.file.Path;
import java.util.Objects;
import java.util.function.Consumer;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import turboheader.il2cpp.model.TypeModel;

/** Imports a TypeModel produced by the native IL2CPP parser. */
public final class NativeIl2CppTypeImportStrategy implements Il2CppTypeImportStrategy {
    private final Program program;
    private final TaskMonitor monitor;
    private final Consumer<String> output;
    private final Consumer<String> errors;

    public NativeIl2CppTypeImportStrategy(Program program, TaskMonitor monitor,
            Consumer<String> output, Consumer<String> errors) {
        this.program = Objects.requireNonNull(program, "program");
        this.monitor = monitor == null ? TaskMonitor.DUMMY : monitor;
        this.output = Objects.requireNonNull(output, "output");
        this.errors = Objects.requireNonNull(errors, "errors");
    }

    @Override
    public void importTypes(Path header, Path offsets, int pointerSize,
            Il2CppLayoutPolicy layoutPolicy) throws Exception {
        if (pointerSize != 4 && pointerSize != 8) {
            throw new IllegalArgumentException(
                    "Program pointer size must be 4 or 8, got " + pointerSize);
        }

        output.accept("TurboHeader: parsing IL2CPP header...");
        long parseStart = System.nanoTime();
        int nativeApi = NativeParser.nativeApiVersion();
        TypeModel.Model model = NativeParser.parse(header, offsets, pointerSize);
        double parseSeconds = (System.nanoTime() - parseStart) / 1_000_000_000.0;

        long parsedFields = model.structures().stream().mapToLong(s -> s.fields().size()).sum();
        output.accept(String.format("TurboHeader: importing %,d structures and %,d fields...",
                model.structures().size(), parsedFields));
        var importer = new GhidraTypeImporter(program, model, monitor,
                nativeLayoutPolicy(layoutPolicy));
        GhidraTypeImporter.ImportStats stats = importer.importTypes();
        for (GhidraTypeImporter.ImportDiagnostic diagnostic : stats.diagnostics()) {
            errors.accept(String.format("TurboHeader: %s.%s at 0x%x: %s",
                    diagnostic.structure(), diagnostic.field(), diagnostic.offset(),
                    diagnostic.reason()));
        }
        output.accept(String.format(
                "TurboHeader native API %d: parsed %,d structures in %.3f s; imported %,d fields into %,d types in %.3f s " +
                "(%,d overlap unions, %,d fallbacks, %,d missing offsets).",
                nativeApi, model.structures().size(), parseSeconds, stats.fields(),
                stats.structures(), stats.elapsedSeconds(), stats.overlapUnions(),
                stats.fallbackFields(), stats.missingOffsets()));

        var evidence = stats.evidenceCounts();
        output.accept(String.format(
                "TurboHeader layout evidence: source=%s schema=%d; %,d sidecar-copied, %,d ABI-defined, " +
                "%,d header-inferred, %,d legacy-unknown imported offsets.",
                model.offsetSource(), model.offsetSchemaVersion(), evidence.sidecarCopied(),
                evidence.abiDefined(), evidence.headerInferred(), evidence.legacyUnknown()));
        var extents = stats.lengthEvidenceCounts();
        output.accept(String.format(
                "TurboHeader extent evidence: %,d sidecar-copied, %,d ABI-defined, " +
                "%,d header-inferred, %,d legacy-unknown structure lengths.",
                extents.sidecarCopied(), extents.abiDefined(), extents.headerInferred(),
                extents.legacyUnknown()));
        if (evidence.headerInferred() > 0) {
            errors.accept(String.format(
                    "TurboHeader warning: %,d field offsets were inferred from il2cpp.h and are not " +
                    "runtime-authoritative.", evidence.headerInferred()));
        }
        if (extents.headerInferred() > 0) {
            errors.accept(ImportDiagnostics.inferredExtentWarning(extents.headerInferred()));
        }
        if (model.missingOffsets() > 0) {
            TypeModel.MissingOffsetReasons reasons = model.missingOffsetReasons();
            output.accept(String.format(
                    "TurboHeader missing offsets: %,d open generic, %,d concrete sidecar absent, " +
                    "%,d unresolved generic parent, %,d object-header offset, %,d unsupported layout" +
                    (reasons.legacyUnclassified() > 0 ? ", %,d legacy unclassified." : "."),
                    reasons.openGenericDefinition(), reasons.concreteInstanceAbsent(),
                    reasons.unresolvedGenericParent(), reasons.objectHeaderOffset(),
                    reasons.unsupportedLayout(), reasons.legacyUnclassified()));
        }
    }

    private static GhidraTypeImporter.LayoutPolicy nativeLayoutPolicy(
            Il2CppLayoutPolicy policy) {
        return switch (policy) {
            case ALLOW_INFERRED -> GhidraTypeImporter.LayoutPolicy.ALLOW_INFERRED;
            case REQUIRE_EXTERNAL_OFFSETS ->
                GhidraTypeImporter.LayoutPolicy.REQUIRE_EXTERNAL_OFFSETS;
            case REQUIRE_AUTHORITATIVE ->
                GhidraTypeImporter.LayoutPolicy.REQUIRE_AUTHORITATIVE;
        };
    }
}
