package turboheader.il2cpp.analysis.interfacecall;

import java.util.NavigableMap;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import turboheader.il2cpp.analysis.pipeline.FunctionProofCoordinator;
import turboheader.il2cpp.metadata.Il2CppInterfaceDispatchCatalog;

final class InterfaceProofWorker
        implements FunctionProofCoordinator.Worker<InterfaceProofWorker.FunctionResult> {
    private static final int DECOMPILE_TIMEOUT_SECONDS = 30;

    private final DecompInterface decompiler = new DecompInterface();
    private final GhidraPcodeInterfaceCallResolver resolver;

    InterfaceProofWorker(Program program, Address interfaceHelper,
            Set<Address> objectNewTargets, NavigableMap<Long, Integer> typeInfoSources,
            Il2CppInterfaceDispatchCatalog catalog) {
        resolver = new GhidraPcodeInterfaceCallResolver(interfaceHelper, objectNewTargets,
                program.getDefaultPointerSize(), typeInfoSources, catalog);
        boolean opened = false;
        try {
            decompiler.toggleCCode(false);
            if (!decompiler.openProgram(program)) {
                throw new IllegalStateException("Ghidra decompiler did not open the program: " +
                        decompiler.getLastMessage());
            }
            if (!decompiler.setSimplificationStyle("normalize")) {
                throw new IllegalStateException("Ghidra decompiler rejected normalize style");
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

    record FunctionResult(GhidraPcodeInterfaceCallResolver.Result resolved,
            long decompilationNanos, long resolutionNanos) {
        FunctionResult {
            if (decompilationNanos < 0 || resolutionNanos < 0 ||
                    (resolved == null && resolutionNanos != 0)) {
                throw new IllegalArgumentException("invalid interface function timing");
            }
        }
    }
}
