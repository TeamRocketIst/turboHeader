// Confirms the behavior of Ghidra's historic full-header parser.
// @category Data Types

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.app.util.cparser.C.CParserUtils.CParseResults;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;

public class VerifyGhidraFullHeaderStaticFields extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Path header = Files.createTempFile("ghidra-static-fields-", ".h");
        try {
            Files.writeString(header,
                    "typedef struct LegacyProbe_StaticFields {\n" +
                    "    int counter;\n" +
                    "    void *current;\n" +
                    "} LegacyProbe_StaticFields;\n" +
                    "typedef struct LegacyProbe_c {\n" +
                    "    LegacyProbe_StaticFields *static_fields;\n" +
                    "} LegacyProbe_c;\n");
            parse(header);
            Structure storage = findStructure("LegacyProbe_StaticFields");
            require(storage != null,
                    "Ghidra did not import the declared static-field structure");
            require(storage.getNumDefinedComponents() == 2,
                    "Ghidra did not retain both static-field components");
            require(Arrays.stream(storage.getDefinedComponents())
                    .anyMatch(component -> "counter".equals(component.getFieldName())),
                    "Ghidra did not retain LegacyProbe_StaticFields.counter");
            require(Arrays.stream(storage.getDefinedComponents())
                    .anyMatch(component -> "current".equals(component.getFieldName())),
                    "Ghidra did not retain LegacyProbe_StaticFields.current");
            println("Ghidra full-header static-field verification passed");
        } finally {
            Files.deleteIfExists(header);
        }
    }

    private void parse(Path header) throws Exception {
        CParseResults result = CParserUtils.parseHeaderFiles(null,
                new String[] { header.toString() }, new String[0],
                currentProgram.getDataTypeManager(), monitor);
        require(result != null, "Ghidra's C parser did not return a datatype");
    }

    private Structure findStructure(String name) {
        Iterator<DataType> types = currentProgram.getDataTypeManager().getAllDataTypes();
        while (types.hasNext()) {
            DataType type = types.next();
            if (type instanceof Structure && type.getName().equals(name)) {
                return (Structure) type;
            }
        }
        return null;
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
