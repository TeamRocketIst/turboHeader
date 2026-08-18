package ghidra.program.model.data;
class BasicDataType implements DataType {
    private final String name;
    private final int length;
    BasicDataType(String name, int length) { this.name=name; this.length=length; }
    public int getLength() { return length; }
    public String getName() { return name; }
    public CategoryPath getCategoryPath() { return new CategoryPath("/"); }
}
