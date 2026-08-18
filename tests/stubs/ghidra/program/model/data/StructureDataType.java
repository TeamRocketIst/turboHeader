package ghidra.program.model.data;
import java.util.*;
public class StructureDataType implements Structure {
    private final CategoryPath path;
    private final String name;
    private int length;
    private String description;
    private final List<DataTypeComponent> components = new ArrayList<>();
    public StructureDataType(CategoryPath path, String name, int length, DataTypeManager dtm) {
        this.path=path; this.name=name; this.length=Math.max(1,length);
    }
    public int getLength(){return length;}
    public String getName(){return name;}
    public CategoryPath getCategoryPath(){return path;}
    public void setPackingEnabled(boolean enabled){}
    public void setLength(int length){this.length=Math.max(1,length); components.removeIf(c -> c.getOffset() >= this.length);}
    public void setDescription(String description){this.description=description;}
    public String getDescription(){return description;}
    public DataTypeComponent[] getDefinedComponents(){return components.toArray(DataTypeComponent[]::new);}
    public void clearAtOffset(int offset){components.removeIf(c -> offset >= c.getOffset() && offset < c.getOffset()+Math.max(1,c.getDataType().getLength()));}
    public DataTypeComponent replaceAtOffset(int offset, DataType type, int ignoredLength, String fieldName, String comment){
        int len=Math.max(1,type.getLength());
        if(offset<0 || offset>=length || (long)offset+len>length) throw new IllegalArgumentException("insufficient space");
        clearAtOffset(offset);
        for(DataTypeComponent c: components){
            int a0=c.getOffset(), a1=a0+Math.max(1,c.getDataType().getLength());
            if(offset<a1 && a0<offset+len) throw new IllegalArgumentException("overlap");
        }
        DataTypeComponent c=new DataTypeComponent(offset,type,fieldName); components.add(c);
        components.sort(Comparator.comparingInt(DataTypeComponent::getOffset));
        return c;
    }
}
