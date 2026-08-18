package ghidra.program.model.data;
public final class DataTypeComponent {
    private final int offset;
    private final DataType dataType;
    private final String fieldName;
    public DataTypeComponent(int offset, DataType dataType, String fieldName) {
        this.offset = offset; this.dataType = dataType; this.fieldName = fieldName;
    }
    public int getOffset() { return offset; }
    public DataType getDataType() { return dataType; }
    public String getFieldName() { return fieldName; }
    public int getLength() { return Math.max(1, dataType.getLength()); }
}
