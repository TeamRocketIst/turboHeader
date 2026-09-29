package turboheader.il2cpp.analysis.delegatecall;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import ghidra.program.model.listing.Function;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

final class DelegateProofCoordinator {
    private static final int MAX_WORKERS = 4;

    private DelegateProofCoordinator() {
    }

    static void validateWorkers(int workers) {
        if (workers < 1 || workers > MAX_WORKERS) {
            throw new IllegalArgumentException("delegate workers must be between 1 and 4");
        }
    }

    static List<FunctionResult> analyze(List<Function> functions, int workers,
            TaskMonitor monitor, WorkerFactory factory) throws Exception {
        validateWorkers(workers);
        List<Function> candidates = List.copyOf(functions);
        Objects.requireNonNull(monitor, "monitor");
        Objects.requireNonNull(factory, "factory");
        monitor.checkCancelled();
        if (candidates.isEmpty()) {
            return List.of();
        }

        int lanes = Math.min(workers, candidates.size());
        var results = new FunctionResult[candidates.size()];
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
            return List.of(results);
        }
        finally {
            monitor.removeCancelledListener(listener);
        }
    }

    private static void runParallel(List<Function> functions, FunctionResult[] results,
            int lanes, TaskMonitor monitor, WorkerFactory factory) throws Exception {
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
                throw new IllegalStateException("delegate worker failed", failure.getCause());
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

    private static void runLane(List<Function> functions, FunctionResult[] results,
            int lane, int lanes, TaskMonitor monitor, WorkerFactory factory) throws Exception {
        monitor.checkCancelled();
        try (Worker worker = factory.open(lane)) {
            for (int index = lane; index < functions.size(); index += lanes) {
                monitor.checkCancelled();
                results[index] = Objects.requireNonNull(
                        worker.analyze(functions.get(index), monitor), "function result");
                monitor.checkCancelled();
            }
        }
    }

    interface WorkerFactory {
        Worker open(int lane) throws Exception;
    }

    interface Worker extends AutoCloseable {
        FunctionResult analyze(Function function, TaskMonitor monitor) throws Exception;

        @Override
        void close();
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
