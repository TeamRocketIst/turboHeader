// Verifies provenance, strict rejection, and mode-switch cleanup in a real Ghidra database.
// @category Data Types

import java.nio.file.Path;
import java.util.Arrays;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Structure;
import turboheader.il2cpp.GhidraTypeImporter;
import turboheader.il2cpp.NativeParser;

public class VerifyTurboHeaderProvenance extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        require(args.length == 3, "expected: il2cpp.h type_offsets.json pointer-size");
        Path header = Path.of(args[0]);
        Path offsets = Path.of(args[1]);
        int pointerSize = Integer.parseInt(args[2]);

        var exact = NativeParser.parse(header, offsets, pointerSize);
        var exactStats = new GhidraTypeImporter(currentProgram, exact, monitor,
                GhidraTypeImporter.LayoutPolicy.REQUIRE_AUTHORITATIVE).importTypes();
        require(exactStats.evidenceCounts().headerInferred() == 0,
                "schema-v3 fixture leaked inferred offsets");
        verifyBase("source=type_offsets.json schema 3", null);

        var inferred = NativeParser.parse(header, null, pointerSize);
        try {
            new GhidraTypeImporter(currentProgram, inferred, monitor,
                    GhidraTypeImporter.LayoutPolicy.REQUIRE_AUTHORITATIVE).importTypes();
            throw new AssertionError("strict policy accepted header-only layout");
        }
        catch (IllegalArgumentException expected) {
            // Validation occurs before the datatype transaction. The exact import remains intact.
        }
        verifyBase("source=type_offsets.json schema 3", null);

        var inferredStats = new GhidraTypeImporter(currentProgram, inferred, monitor,
                GhidraTypeImporter.LayoutPolicy.ALLOW_INFERRED).importTypes();
        require(inferredStats.evidenceCounts().headerInferred() > 0,
                "header-only import reported no inferred offsets");
        verifyBase("not runtime-authoritative", "Offset inferred from natural il2cpp.h layout");

        new GhidraTypeImporter(currentProgram, exact, monitor,
                GhidraTypeImporter.LayoutPolicy.REQUIRE_AUTHORITATIVE).importTypes();
        verifyBase("source=type_offsets.json schema 3", null);

        println("TurboHeader real-Ghidra provenance verification passed");
    }

    private void verifyBase(String descriptionFragment, String fieldCommentFragment) {
        var type = currentProgram.getDataTypeManager().getDataType(
                new DataTypePath(GhidraTypeImporter.ROOT, "Base_o"));
        require(type instanceof Structure, "Base_o is missing");
        Structure base = (Structure) type;
        require(base.getDescription().contains(descriptionFragment),
                "unexpected Base_o description: " + base.getDescription());
        DataTypeComponent value = Arrays.stream(base.getDefinedComponents())
                .filter(component -> "a".equals(component.getFieldName()))
                .findFirst().orElseThrow(() -> new AssertionError("Base_o.a is missing"));
        if (fieldCommentFragment == null) {
            require(value.getComment() == null, "stale provenance comment: " + value.getComment());
        }
        else {
            require(value.getComment() != null && value.getComment().contains(fieldCommentFragment),
                    "missing inferred provenance comment: " + value.getComment());
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
