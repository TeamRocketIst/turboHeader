// Measures the bounded global analyzers used by the fast export profile.
// @category Tests

import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;

public class VerifyTurboHeaderGlobalAnalysis extends GhidraScript {
    private static final List<String> ANALYZERS = List.of(
            "AARCH64 ELF PLT Thunks");

    @Override
    protected void run() throws Exception {
        var options = currentProgram.getOptions("Analyzers");
        for (String option : options.getOptionNames()) {
            if (options.getType(option).toString().equals("BOOLEAN_TYPE")) {
                options.setBoolean(option, false);
            }
        }
        for (String analyzer : ANALYZERS) {
            if (options.contains(analyzer)) {
                options.setBoolean(analyzer, true);
            }
        }
        String comments = "GCC Exception Handlers.Create Try Catch Comments";
        if (options.contains(comments)) {
            options.setBoolean(comments, true);
        }

        var manager = AutoAnalysisManager.getAnalysisManager(currentProgram);
        manager.initializeOptions();
        int beginCatchBefore = countFunctionsContaining("__cxa_begin_catch");
        int endCatchBefore = countFunctionsContaining("__cxa_end_catch");
        var scheduled = new ArrayList<String>();
        for (String name : ANALYZERS) {
            var analyzer = manager.getAnalyzer(name);
            if (analyzer == null || !analyzer.canAnalyze(currentProgram)) {
                continue;
            }
            manager.scheduleOneTimeAnalysis(analyzer, currentProgram.getMemory());
            scheduled.add(name);
        }

        long started = System.nanoTime();
        manager.startAnalysis(monitor, true);
        double seconds = (System.nanoTime() - started) / 1_000_000_000.0;
        int beginCatch = countFunctionsContaining("__cxa_begin_catch");
        int endCatch = countFunctionsContaining("__cxa_end_catch");
        println(String.format(
                "TurboHeader global analysis verification: analyzers=%s elapsed=%.3f s " +
                "begin_catch=%d->%d end_catch=%d->%d",
                scheduled, seconds, beginCatchBefore, beginCatch, endCatchBefore, endCatch));
    }

    private int countFunctionsContaining(String needle) {
        int count = 0;
        var functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            if (functions.next().getName().contains(needle)) {
                count++;
            }
        }
        return count;
    }
}
