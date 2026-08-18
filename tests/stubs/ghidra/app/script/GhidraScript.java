package ghidra.app.script;
import java.io.File;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
public abstract class GhidraScript {
    protected Program currentProgram = new Program();
    protected TaskMonitor monitor = TaskMonitor.DUMMY;
    protected abstract void run() throws Exception;
    protected String[] getScriptArgs(){return new String[0];}
    protected File askFile(String title,String approve){return new File(".");}
    protected boolean askYesNo(String title,String question){return false;}
    protected void println(String text){System.out.println(text);}
    protected void printerr(String text){System.err.println(text);}
}
