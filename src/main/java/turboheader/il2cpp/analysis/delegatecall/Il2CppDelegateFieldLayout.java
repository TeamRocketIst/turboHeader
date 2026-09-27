package turboheader.il2cpp.analysis.delegatecall;

import java.util.Objects;
import java.util.Optional;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Program;
import turboheader.il2cpp.types.GhidraTypeImporter;

/** Offsets recovered from the imported System.Delegate layout. */
public record Il2CppDelegateFieldLayout(long invokeTargetOffset,
        long methodInfoOffset, long methodCodeOffset) {
    private static final String DELEGATE_OBJECT = "System_Delegate_o";
    private static final String DELEGATE_FIELDS = "System_Delegate_Fields";

    public Il2CppDelegateFieldLayout {
        if (invokeTargetOffset < 0 || methodInfoOffset < 0 || methodCodeOffset < 0 ||
                invokeTargetOffset == methodInfoOffset ||
                invokeTargetOffset == methodCodeOffset ||
                methodInfoOffset == methodCodeOffset) {
            throw new IllegalArgumentException("invalid delegate field offsets");
        }
    }

    public static Optional<Il2CppDelegateFieldLayout> read(Program program) {
        Objects.requireNonNull(program, "program");
        var manager = program.getDataTypeManager();
        DataType objectType = manager.getDataType(
                new DataTypePath(GhidraTypeImporter.ROOT, DELEGATE_OBJECT));
        if (!(unwrap(objectType) instanceof Structure object)) {
            return Optional.empty();
        }

        int objectFieldsCount = fieldCount(object, "fields");
        if (objectFieldsCount == 0) {
            return readFields(object, 0, program.getDefaultPointerSize());
        }
        if (objectFieldsCount != 1) {
            return Optional.empty();
        }

        DataType fieldsType = manager.getDataType(
                new DataTypePath(GhidraTypeImporter.ROOT, DELEGATE_FIELDS));
        if (!(unwrap(fieldsType) instanceof Structure fields)) {
            return Optional.empty();
        }
        DataTypeComponent objectFields = uniqueField(object, "fields");
        if (objectFields == null ||
                !unwrap(objectFields.getDataType()).getDataTypePath().equals(
                        fields.getDataTypePath()) ||
                !unwrap(objectFields.getDataType()).isEquivalent(fields)) {
            return Optional.empty();
        }
        return readFields(fields, objectFields.getOffset(),
                program.getDefaultPointerSize());
    }

    private static Optional<Il2CppDelegateFieldLayout> readFields(
            Structure fields, long base, int pointerSize) {
        DataTypeComponent invokeTarget = uniqueField(fields, "invoke_impl");
        DataTypeComponent methodInfo = uniqueField(fields, "method");
        DataTypeComponent methodCode = uniqueField(fields, "method_code");
        if (invokeTarget == null || methodInfo == null || methodCode == null ||
                invokeTarget.getLength() != pointerSize ||
                methodInfo.getLength() != pointerSize ||
                methodCode.getLength() != pointerSize) {
            return Optional.empty();
        }

        try {
            return Optional.of(new Il2CppDelegateFieldLayout(
                    Math.addExact(base, invokeTarget.getOffset()),
                    Math.addExact(base, methodInfo.getOffset()),
                    Math.addExact(base, methodCode.getOffset())));
        }
        catch (ArithmeticException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    private static int fieldCount(Structure structure, String name) {
        int count = 0;
        for (DataTypeComponent component : structure.getDefinedComponents()) {
            if (name.equals(component.getFieldName())) {
                count++;
            }
        }
        return count;
    }

    private static DataTypeComponent uniqueField(Structure structure, String name) {
        DataTypeComponent match = null;
        for (DataTypeComponent component : structure.getDefinedComponents()) {
            if (!name.equals(component.getFieldName())) {
                continue;
            }
            if (match != null) {
                return null;
            }
            match = component;
        }
        return match;
    }

    private static DataType unwrap(DataType type) {
        DataType current = type;
        while (current instanceof TypeDef definition) {
            current = definition.getDataType();
        }
        return current;
    }
}
