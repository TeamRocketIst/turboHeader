package turboheader.il2cpp;

import java.nio.file.Path;

/** Small non-Ghidra smoke-test utility for JNI and model decoding. */
public final class ModelDumpCli {
    private ModelDumpCli() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1 || args.length > 3) {
            System.err.println("usage: ModelDumpCli il2cpp.h [type_offsets.json|dump.cs|-] [pointer-size]");
            System.exit(2);
        }
        Path offsets = args.length >= 2 && !args[1].equals("-") ? Path.of(args[1]) : null;
        int pointerSize = args.length >= 3 ? Integer.parseInt(args[2]) : 8;
        long start = System.nanoTime();
        TypeModel.Model model = NativeParser.parse(Path.of(args[0]), offsets, pointerSize);
        long elapsed = System.nanoTime() - start;
        long fields = model.structures().stream().mapToLong(s -> s.fields().size()).sum();
        System.out.printf("structures=%d fields=%d missingOffsets=%d pointerSize=%d " +
                        "source=%s schema=%d elapsedMs=%.3f%n",
                model.structures().size(), fields, model.missingOffsets(), model.pointerSize(),
                model.offsetSource(), model.offsetSchemaVersion(), elapsed / 1_000_000.0);
        TypeModel.EvidenceCounts offsetEvidence = model.evidenceCounts();
        TypeModel.EvidenceCounts extents = model.lengthEvidenceCounts();
        System.out.printf("offsetEvidence=copied:%d,abi:%d,inferred:%d,legacy:%d%n",
                offsetEvidence.sidecarCopied(), offsetEvidence.abiDefined(),
                offsetEvidence.headerInferred(), offsetEvidence.legacyUnknown());
        System.out.printf("extentEvidence=copied:%d,abi:%d,inferred:%d,legacy:%d%n",
                extents.sidecarCopied(), extents.abiDefined(), extents.headerInferred(),
                extents.legacyUnknown());
        TypeModel.MissingOffsetReasons reasons = model.missingOffsetReasons();
        System.out.printf("missingReasons=openGeneric:%d,concreteAbsent:%d,genericParent:%d," +
                        "objectHeader:%d,unsupported:%d,legacy:%d%n",
                reasons.openGenericDefinition(), reasons.concreteInstanceAbsent(),
                reasons.unresolvedGenericParent(), reasons.objectHeaderOffset(),
                reasons.unsupportedLayout(), reasons.legacyUnclassified());
    }
}
