package ghidra.program.model.data;
import java.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
public class DataTypeManager {
    private final Map<DataTypePath,DataType> types=new HashMap<>();
    private Map<DataTypePath,DataType> transactionSnapshot;
    private int transactions;
    public void addDataTypes(Collection<DataType> dataTypes,DataTypeConflictHandler handler,TaskMonitor monitor) throws CancelledException {
        for(DataType dt:dataTypes){monitor.checkCancelled();addDataType(dt,handler);}
    }
    public DataType addDataType(DataType dt,DataTypeConflictHandler handler){
        DataTypePath p=new DataTypePath(dt.getCategoryPath(),dt.getName());
        if(handler==DataTypeConflictHandler.KEEP_HANDLER && types.containsKey(p)) return types.get(p);
        types.put(p,dt);return dt;
    }
    public DataType getDataType(DataTypePath path){return types.get(path);}
    public DataType getPointer(DataType type,int size){return new PointerDataType(type,size);}
    public Iterator<DataType> getAllDataTypes(){return new ArrayList<>(types.values()).iterator();}
    public boolean remove(DataType type){return types.remove(new DataTypePath(type.getCategoryPath(),type.getName()))!=null;}
    public void remove(List<DataType> dataTypes,TaskMonitor monitor) throws CancelledException {
        for(DataType type:dataTypes){monitor.checkCancelled();remove(type);}
    }
    public Map<DataTypePath,DataType> snapshot(){return new HashMap<>(types);}
    public void restore(Map<DataTypePath,DataType> snapshot){types.clear();types.putAll(snapshot);}
    public int startTransaction(String description){transactionSnapshot=snapshot();return ++transactions;}
    public boolean endTransaction(int id,boolean commit){if(!commit)restore(transactionSnapshot);transactionSnapshot=null;return commit;}
    public int getTransactionCount(){return transactions;}
}
