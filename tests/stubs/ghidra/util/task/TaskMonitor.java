package ghidra.util.task;
import ghidra.util.exception.CancelledException;
public class TaskMonitor {
    public static final TaskMonitor DUMMY = new TaskMonitor();
    private long progress;
    public void initialize(long maximum) {}
    public void setMessage(String message) {}
    public void checkCancelled() throws CancelledException {}
    public void incrementProgress(long amount) { progress += amount; }
    public long getProgress() { return progress; }
}
