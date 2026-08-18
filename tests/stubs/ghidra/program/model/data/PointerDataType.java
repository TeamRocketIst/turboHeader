package ghidra.program.model.data;
public class PointerDataType implements DataType {
    private final DataType base; private final int size;
    public PointerDataType(DataType base,int size){this.base=base;this.size=size;}
    public int getLength(){return size;}
    public String getName(){return base.getName()+" *";}
    public CategoryPath getCategoryPath(){return base.getCategoryPath();}
    public DataType getDataType(){return base;}
}
