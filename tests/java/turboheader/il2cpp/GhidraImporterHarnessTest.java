package turboheader.il2cpp;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public final class GhidraImporterHarnessTest {
    public static void main(String[] args) throws Exception {
        TypeModel.Model model = NativeParser.parse(Path.of(args[0]), Path.of(args[1]), 8);
        Program program = new Program();
        GhidraTypeImporter importer = new GhidraTypeImporter(program, model, TaskMonitor.DUMMY);
        GhidraTypeImporter.ImportStats stats = importer.importTypes();
        check(stats.structures() == 6, "structure count");
        check(stats.fields() == 18, "field count");
        check(stats.overlapUnions() == 2, "overlap union count");
        check(stats.fallbackFields() == 0, "fallbacks");

        Structure derived = (Structure) program.getDataTypeManager().getDataType(
                new DataTypePath(GhidraTypeImporter.ROOT, "Derived_o"));
        Map<Integer,DataTypeComponent> at = Arrays.stream(derived.getDefinedComponents())
                .collect(Collectors.toMap(DataTypeComponent::getOffset, c -> c));
        check(at.get(24).getDataType() instanceof Structure, "nested value type");
        check(at.get(32).getDataType() instanceof ArrayDataType && at.get(32).getDataType().getLength() == 12,
                "fixed array");
        check(at.get(44).getDataType() instanceof Union && at.get(44).getDataType().getLength() == 4,
                "same-offset union");
        check(at.get(48).getDataType() instanceof Union && at.get(48).getDataType().getLength() == 8,
                "shifted overlap union");
        Union shifted = (Union) at.get(48).getDataType();
        check(shifted.getDefinedComponents().length == 2, "shifted union views");
        check(at.get(56).getFieldName().equals("a"), "shadowed field");
        System.out.println("Ghidra importer harness passed: " + stats);
    }

    private static void check(boolean condition, String label) {
        if (!condition) throw new AssertionError(label);
    }
}
