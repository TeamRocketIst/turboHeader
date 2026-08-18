package ghidra.program.model.data;
public final class AbstractIntegerDataType {
    public static DataType getSignedDataType(int bytes, DataTypeManager dtm){return new BasicDataType("int"+(bytes*8)+"_t",bytes);}
    public static DataType getUnsignedDataType(int bytes, DataTypeManager dtm){return new BasicDataType("uint"+(bytes*8)+"_t",bytes);}
}
