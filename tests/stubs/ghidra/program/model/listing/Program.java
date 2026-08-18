package ghidra.program.model.listing;
import java.util.Map;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
public class Program {
    private final DataTypeManager manager=new DataTypeManager();
    private final int pointerSize;
    private Map<DataTypePath,DataType> snapshot;
    private int transactions;
    public Program(){this(8);}
    public Program(int pointerSize){this.pointerSize=pointerSize;}
    public DataTypeManager getDataTypeManager(){return manager;}
    public int startTransaction(String description){snapshot=manager.snapshot();return ++transactions;}
    public void endTransaction(int id,boolean commit){if(!commit)manager.restore(snapshot);snapshot=null;}
    public int getDefaultPointerSize(){return pointerSize;}
    public int getTransactionCount(){return transactions;}
}
