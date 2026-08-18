package ghidra.program.model.data;
public class ArrayDataType implements Array {
    private final DataType base; private final int count;
    public ArrayDataType(DataType base,int count,int elementLength,DataTypeManager dtm){this.base=base;this.count=count;}
    public int getLength(){return Math.max(0,base.getLength()*count);}
    public String getName(){return base.getName()+"["+count+"]";}
    public CategoryPath getCategoryPath(){return base.getCategoryPath();}
    public DataType getDataType(){return base;}
    public int getNumElements(){return count;}
}
