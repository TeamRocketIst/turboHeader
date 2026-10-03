package turboheader.il2cpp.analysis.pipeline;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReferenceArray;

import ghidra.program.model.listing.Function;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import turboheader.il2cpp.decompile.Il2CppDecompilationPolicy;

public final class FunctionProofCoordinator {
    private FunctionProofCoordinator() {
    }

    public static void validateWorkers(int workers) {
        if (workers < 1 || workers > Il2CppDecompilationPolicy.MAX_PROOF_WORKERS) {
            throw new IllegalArgumentException("proof workers must be between 1 and " +
                    Il2CppDecompilationPolicy.MAX_PROOF_WORKERS);
        }
    }

    public static <R> List<R> analyze(List<Function> functions, int workers,
            TaskMonitor monitor, WorkerFactory<R> factory) throws Exception {
        validateWorkers(workers);
        List<Function> candidates = List.copyOf(functions);
        Objects.requireNonNull(monitor, "monitor");
        Objects.requireNonNull(factory, "factory");
        monitor.checkCancelled();
        if (candidates.isEmpty()) {
            return List.of();
        }

        int lanes = Math.min(workers, candidates.size());
        var results = new AtomicReferenceArray<R>(candidates.size());
        var localMonitor = new TaskMonitorAdapter(true);
        CancelledListener listener = localMonitor::cancel;
        monitor.addCancelledListener(listener);
        try {
            if (monitor.isCancelled()) {
                localMonitor.cancel();
            }
            localMonitor.checkCancelled();
            if (lanes == 1) {
                runLane(candidates, results, 0, 1, localMonitor, factory);
            }
            else {
                runParallel(candidates, results, lanes, localMonitor, factory);
            }
            localMonitor.checkCancelled();
            List<R> ordered = new ArrayList<>(candidates.size());
            for (int index = 0; index < candidates.size(); index++) {
                ordered.add(results.get(index));
            }
            return List.copyOf(ordered);
        }
        finally {
            monitor.removeCancelledListener(listener);
        }
    }

    private static <R> void runParallel(List<Function> functions, AtomicReferenceArray<R> results,
            int lanes, TaskMonitor monitor, WorkerFactory<R> factory) throws Exception {
        // Closing the executor joins workers before the caller can publish changes.
        try (var executor = Executors.newFixedThreadPool(lanes)) {
            var completed = new ExecutorCompletionService<Void>(executor);
            List<Future<Void>> futures = new ArrayList<>(lanes);
            boolean succeeded = false;
            try {
                for (int lane = 0; lane < lanes; lane++) {
                    int laneIndex = lane;
                    futures.add(completed.submit(() -> {
                        runLane(functions, results, laneIndex, lanes, monitor, factory);
                        return null;
                    }));
                }
                for (int lane = 0; lane < lanes; lane++) {
                    completed.take().get();
                }
                succeeded = true;
            }
            catch (ExecutionException failure) {
                if (failure.getCause() instanceof Exception cause) {
                    throw cause;
                }
                if (failure.getCause() instanceof Error cause) {
                    throw cause;
                }
                throw new IllegalStateException("proof worker failed", failure.getCause());
            }
            catch (InterruptedException failure) {
                Thread.currentThread().interrupt();
                throw failure;
            }
            finally {
                if (!succeeded) {
                    monitor.cancel();
                    for (var future : futures) {
                        future.cancel(true);
                    }
                }
            }
        }
    }

    private static <R> void runLane(List<Function> functions, AtomicReferenceArray<R> results,
            int lane, int lanes, TaskMonitor monitor, WorkerFactory<R> factory) throws Exception {
        monitor.checkCancelled();
        try (Worker<R> worker = Objects.requireNonNull(factory.open(lane), "proof worker")) {
            for (int index = lane; index < functions.size(); index += lanes) {
                monitor.checkCancelled();
                results.set(index, Objects.requireNonNull(
                        worker.analyze(functions.get(index), monitor), "function result"));
                monitor.checkCancelled();
            }
        }
    }

    public interface WorkerFactory<R> {
        Worker<R> open(int lane) throws Exception;
    }

    public interface Worker<R> extends AutoCloseable {
        R analyze(Function function, TaskMonitor monitor) throws Exception;

        @Override
        void close();
    }
}
