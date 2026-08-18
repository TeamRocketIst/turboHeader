package ghidra.program.model.data;
public class FunctionDefinitionDataType implements DataType {
    private final CategoryPath path;
    private final String name;
    private DataType returnType=VoidDataType.dataType;
    private ParameterDefinition[] arguments=new ParameterDefinition[0];
    private String comment;
    private boolean varArgs;
    public FunctionDefinitionDataType(CategoryPath path,String name,DataTypeManager dtm){this.path=path;this.name=name;}
    public void setReturnType(DataType type){returnType=type;}
    public void setArguments(ParameterDefinition... definitions){arguments=definitions;}
    public void setComment(String value){comment=value;}
    public void setVarArgs(boolean value){varArgs=value;}
    public DataType getReturnType(){return returnType;}
    public ParameterDefinition[] getArguments(){return arguments;}
    public boolean hasVarArgs(){return varArgs;}
    public int getLength(){return -1;}
    public String getName(){return name;}
    public CategoryPath getCategoryPath(){return path;}
    public String getDescription(){return comment;}
}
