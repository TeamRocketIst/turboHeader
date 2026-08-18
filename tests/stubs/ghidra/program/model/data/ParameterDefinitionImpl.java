package ghidra.program.model.data;
public class ParameterDefinitionImpl implements ParameterDefinition {
    private final DataType type;
    public ParameterDefinitionImpl(String name,DataType type,String comment){this.type=type;}
    public DataType getDataType(){return type;}
}
