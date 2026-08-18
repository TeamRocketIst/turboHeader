package ghidra.program.model.data;
public interface Union extends DataType {
    void setPackingEnabled(boolean enabled);
    DataTypeComponent add(DataType type, int length, String name, String comment);
    DataTypeComponent[] getDefinedComponents();
}
