package ghidra.program.model.data;
public final class DataTypeConflictHandler {
    public static final DataTypeConflictHandler REPLACE_HANDLER = new DataTypeConflictHandler();
    public static final DataTypeConflictHandler KEEP_HANDLER = new DataTypeConflictHandler();
    private DataTypeConflictHandler() {}
}
