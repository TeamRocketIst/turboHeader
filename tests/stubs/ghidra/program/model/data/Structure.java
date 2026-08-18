package ghidra.program.model.data;
public interface Structure extends DataType {
    void setPackingEnabled(boolean enabled);
    void setLength(int length);
    void setDescription(String description);
    DataTypeComponent[] getDefinedComponents();
    void clearAtOffset(int offset);
    DataTypeComponent replaceAtOffset(int offset, DataType type, int length, String name, String comment);
}
