package ghidra.program.model.data;
import java.util.*;
public class UnionDataType implements Union {
    private final CategoryPath path;
    private final String name;
    private final List<DataTypeComponent> components = new ArrayList<>();
    private String description;
    public UnionDataType(CategoryPath path, String name, DataTypeManager dtm){this.path=path;this.name=name;}
    public void setPackingEnabled(boolean enabled){}
    public DataTypeComponent add(DataType type,int length,String fieldName,String comment){
        DataTypeComponent c=new DataTypeComponent(0,type,fieldName);components.add(c);return c;
    }
    public int getLength(){return components.stream().mapToInt(c->Math.max(1,c.getDataType().getLength())).max().orElse(1);}
    public String getName(){return name;}
    public CategoryPath getCategoryPath(){return path;}
    public void setDescription(String description){this.description=description;}
    public String getDescription(){return description;}
    public DataTypeComponent[] getDefinedComponents(){return components.toArray(DataTypeComponent[]::new);}
}
