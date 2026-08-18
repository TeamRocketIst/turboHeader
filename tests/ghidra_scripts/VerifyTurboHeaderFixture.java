// Verifies the repository's sample IL2CPP import in a real Ghidra program.
// @category Data Types

import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import turboheader.il2cpp.GhidraTypeImporter;

public class VerifyTurboHeaderFixture extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var type = currentProgram.getDataTypeManager().getDataType(
                new DataTypePath(GhidraTypeImporter.ROOT, "Derived_o"));
        require(type instanceof Structure, "Derived_o is missing or not a structure");
        Structure derived = (Structure) type;
        require(derived.getLength() == 60, "Derived_o length is " + derived.getLength());

        Map<Integer, DataTypeComponent> at = Arrays.stream(derived.getDefinedComponents())
                .collect(Collectors.toMap(DataTypeComponent::getOffset, c -> c));
        require(at.get(24).getDataType() instanceof Structure, "nested Vec2 value type missing");
        require(at.get(32).getDataType() instanceof Array && at.get(32).getLength() == 12,
                "int32_t[3] missing");
        require(at.get(44).getDataType() instanceof Union, "same-offset union missing");
        require(at.get(48).getDataType() instanceof Union, "shifted-overlap union missing");
        require("a".equals(at.get(56).getFieldName()), "shadowed field not retained");
        println("TurboHeader real-Ghidra fixture verification passed");
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
