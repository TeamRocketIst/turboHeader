package turboheader.il2cpp;

import java.nio.file.Path;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/** Validates and imports an arbitrary generated model with the lightweight Ghidra test doubles. */
public final class CorpusModelValidation {
    private CorpusModelValidation() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2 && args.length != 3) {
            throw new IllegalArgumentException("expected: il2cpp.h type_offsets.json [pointer-size]");
        }
        int pointerSize = args.length == 3 ? Integer.parseInt(args[2]) : 8;
        var model = NativeParser.parse(Path.of(args[0]), Path.of(args[1]), pointerSize);
        var stats = new GhidraTypeImporter(new Program(pointerSize), model, TaskMonitor.DUMMY,
                GhidraTypeImporter.LayoutPolicy.REQUIRE_EXTERNAL_OFFSETS).importTypes();
        System.out.printf("validated %,d structures and %,d fields (%d missing offsets)%n",
                stats.structures(), stats.fields(), stats.missingOffsets());
    }
}
