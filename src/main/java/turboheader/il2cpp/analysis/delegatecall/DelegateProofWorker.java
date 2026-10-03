package turboheader.il2cpp.analysis.delegatecall;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import turboheader.il2cpp.analysis.pipeline.FunctionProofCoordinator;

final class DelegateProofWorker
        implements FunctionProofCoordinator.Worker<DelegateProofWorker.FunctionResult> {
    private static final int DECOMPILE_TIMEOUT_SECONDS = 30;

    private final DecompInterface decompiler = new DecompInterface();
    private final GhidraPcodeDelegateCallResolver resolver;

    DelegateProofWorker(Program program, Il2CppDelegateFieldLayout layout,
            Il2CppDelegatePrototypeCatalog prototypes) {
        resolver = new GhidraPcodeDelegateCallResolver(layout, prototypes);
        boolean opened = false;
        try {
            decompiler.toggleCCode(false);
            if (!decompiler.openProgram(program)) {
                throw new IllegalStateException("Ghidra decompiler did not open the program: " +
                        decompiler.getLastMessage());
            }
            if (!decompiler.setSimplificationStyle("decompile")) {
                throw new IllegalStateException("Ghidra decompiler rejected decompile style");
            }
            opened = true;
        }
        finally {
            if (!opened) {
                close();
            }
        }
    }

    @Override
    public FunctionResult analyze(Function function, TaskMonitor monitor) throws Exception {
        monitor.checkCancelled();
        long started = System.nanoTime();
        var result = decompiler.decompileFunction(function, DECOMPILE_TIMEOUT_SECONDS, monitor);
        long decompilationNanos = System.nanoTime() - started;
        monitor.checkCancelled();
        if (!result.decompileCompleted() || result.getHighFunction() == null) {
            return new FunctionResult(null, decompilationNanos, 0);
        }
        started = System.nanoTime();
        var resolved = resolver.resolve(result.getHighFunction());
        long resolutionNanos = System.nanoTime() - started;
        monitor.checkCancelled();
        return new FunctionResult(resolved, decompilationNanos, resolutionNanos);
    }

    @Override
    public void close() {
        try {
            decompiler.closeProgram();
        }
        finally {
            decompiler.dispose();
        }
    }

    record FunctionResult(GhidraPcodeDelegateCallResolver.Result resolved,
            long decompilationNanos, long resolutionNanos) {
        FunctionResult {
            if (decompilationNanos < 0 || resolutionNanos < 0 ||
                    (resolved == null && resolutionNanos != 0)) {
                throw new IllegalArgumentException("invalid delegate function timing");
            }
        }
    }
}
