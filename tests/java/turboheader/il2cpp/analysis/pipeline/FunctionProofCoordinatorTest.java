package turboheader.il2cpp.analysis.pipeline;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public final class FunctionProofCoordinatorTest {
    public static void main(String[] args) throws Exception {
        orderedLanes(1, 12);
        orderedLanes(2, 12);
        orderedLanes(4, 12);
        orderedLanes(4, 2);
        orderedLanes(8, 16);
        orderedLanes(8, 2);
        invalidRequests();
        for (int workers : new int[] { 2, 8 }) {
            failureDrainsWorkers(workers, true);
            failureDrainsWorkers(workers, false);
            cancellationDrainsWorkers(workers, false);
            cancellationDrainsWorkers(workers, true);
            closeFailure(workers);
        }
        nullResults();
        inputSnapshot();
        workerError();
        System.out.println("FunctionProofCoordinatorTest: 20 cases passed");
    }

    private static void orderedLanes(int workers, int count) throws Exception {
        var functions = functions(count);
        int lanes = Math.min(workers, count);
        var opened = new AtomicInteger();
        var closed = new AtomicInteger();
        var closing = new CountDownLatch[lanes];
        for (int lane = 0; lane < lanes; lane++) {
            closing[lane] = new CountDownLatch(1);
        }
        var results = FunctionProofCoordinator.analyze(functions, workers, TaskMonitor.DUMMY,
                lane -> {
                    opened.incrementAndGet();
                    Thread owner = Thread.currentThread();
                    return new FunctionProofCoordinator.Worker<Integer>() {
                        private int next = lane;

                        public Integer analyze(Function function, TaskMonitor monitor) {
                            require(Thread.currentThread() == owner, "worker changed threads");
                            require(function == functions.get(next), "round-robin order differs");
                            next += lanes;
                            return result(Integer.parseInt(function.getName()));
                        }

                        public void close() {
                            require(Thread.currentThread() == owner, "close changed threads");
                            if (lane + 1 < lanes) {
                                awaitUnchecked(closing[lane + 1]);
                            }
                            closed.incrementAndGet();
                            closing[lane].countDown();
                        }
                    };
                });
        require(opened.get() == lanes && closed.get() == lanes, "worker lifecycle differs");
        for (int index = 0; index < count; index++) {
            require(results.get(index).equals(result(index)), "results are out of order");
        }
        expect(UnsupportedOperationException.class, () -> results.clear());
    }

    private static void invalidRequests() throws Exception {
        FunctionProofCoordinator.WorkerFactory<Integer> forbidden = lane -> {
            throw new AssertionError("unexpected worker");
        };
        for (int workers : new int[] { -1, 0, 9, Integer.MAX_VALUE }) {
            expect(IllegalArgumentException.class, () -> FunctionProofCoordinator.analyze(
                    functions(1), workers, TaskMonitor.DUMMY, forbidden));
        }
        require(FunctionProofCoordinator.analyze(List.of(), 4, TaskMonitor.DUMMY,
                forbidden).isEmpty(), "empty input opened workers");
        var cancelled = new TaskMonitorAdapter(true);
        cancelled.cancel();
        expect(CancelledException.class, () -> FunctionProofCoordinator.analyze(
                functions(1), 1, cancelled, forbidden));
        var cancelledOnRegistration = new TaskMonitorAdapter(true) {
            public void addCancelledListener(CancelledListener listener) {
                cancel();
                super.addCancelledListener(listener);
            }
        };
        expect(CancelledException.class, () -> FunctionProofCoordinator.analyze(
                functions(1), 1, cancelledOnRegistration, forbidden));
    }

    private static void failureDrainsWorkers(int workers, boolean setupFailure) throws Exception {
        var peerStarted = new CountDownLatch(workers - 1);
        var closed = new AtomicInteger();
        var parent = new TaskMonitorAdapter(true);
        var failure = new IllegalStateException("synthetic failure");
        Throwable thrown = expect(IllegalStateException.class,
                () -> FunctionProofCoordinator.analyze(functions(workers), workers, parent, lane -> {
                    if (lane == 0 && setupFailure) {
                        await(peerStarted);
                        throw failure;
                    }
                    return new FunctionProofCoordinator.Worker<Integer>() {
                        public Integer analyze(Function function, TaskMonitor monitor) throws Exception {
                            if (lane == 0) {
                                await(peerStarted);
                                throw failure;
                            }
                            waitForCancellation(monitor, peerStarted);
                            return result(1);
                        }

                        public void close() {
                            closed.incrementAndGet();
                        }
                    };
                }));
        require(thrown == failure, "original failure was lost");
        require(closed.get() == (setupFailure ? workers - 1 : workers),
                "workers escaped failure cleanup");
        require(!parent.isCancelled(), "internal failure cancelled the caller's monitor");
    }

    private static void cancellationDrainsWorkers(int workers, boolean interrupt) throws Exception {
        var started = new CountDownLatch(workers);
        var closing = new CountDownLatch(workers);
        var releaseClose = new CountDownLatch(1);
        var closed = new AtomicInteger();
        var parent = new TaskMonitorAdapter(true);
        var failure = new AtomicReference<Throwable>();
        var interrupted = new AtomicReference<Boolean>(false);
        Thread caller = new Thread(() -> {
            try {
                FunctionProofCoordinator.analyze(functions(workers), workers, parent, lane ->
                        new FunctionProofCoordinator.Worker<Integer>() {
                            public Integer analyze(Function function, TaskMonitor monitor) throws Exception {
                                waitForCancellation(monitor, started);
                                return result(lane);
                            }

                            public void close() {
                                closing.countDown();
                                // Cleanup must finish even after Future.cancel(true).
                                awaitCleanup(releaseClose);
                                closed.incrementAndGet();
                            }
                        });
                failure.set(new AssertionError("cancelled analysis returned results"));
            }
            catch (Throwable thrown) {
                failure.set(thrown);
                interrupted.set(Thread.currentThread().isInterrupted());
            }
        }, "proof-test-caller");
        caller.start();
        try {
            await(started);
            if (interrupt) {
                caller.interrupt();
            }
            else {
                parent.cancel();
            }
            await(closing);
            require(caller.isAlive(), "coordinator returned before worker cleanup");
            releaseClose.countDown();
            caller.join(5000);
            require(!caller.isAlive(), "coordinator did not drain workers");
            require(closed.get() == workers, "cancelled workers were not closed");
            Class<?> expected = interrupt ? InterruptedException.class : CancelledException.class;
            require(expected.isInstance(failure.get()), "wrong cancellation: " + failure.get());
            require(interrupted.get() == interrupt, "interrupt status differs");
            require(parent.isCancelled() != interrupt, "parent cancellation changed");
        }
        finally {
            releaseClose.countDown();
            parent.cancel();
            caller.interrupt();
            caller.join(5000);
        }
    }

    private static void closeFailure(int workers) throws Exception {
        var closed = new AtomicInteger();
        var started = new CountDownLatch(workers);
        expect(IllegalStateException.class, () -> FunctionProofCoordinator.analyze(
                functions(workers), workers, TaskMonitor.DUMMY,
                lane -> new FunctionProofCoordinator.Worker<Integer>() {
                    public Integer analyze(Function function, TaskMonitor monitor) throws Exception {
                        started.countDown();
                        await(started);
                        return result(lane);
                    }

                    public void close() {
                        closed.incrementAndGet();
                        throw new IllegalStateException("synthetic close failure");
                    }
                }));
        require(closed.get() == workers, "failing workers were not closed");
    }

    private static Integer result(int index) {
        return index;
    }

    private static void nullResults() throws Exception {
        for (int workers : new int[] { 1, 2 }) {
            var closed = new AtomicInteger();
            expect(NullPointerException.class, () -> FunctionProofCoordinator.analyze(
                    functions(2), workers, TaskMonitor.DUMMY, lane -> null));
            expect(NullPointerException.class, () -> FunctionProofCoordinator.analyze(
                    functions(2), workers, TaskMonitor.DUMMY,
                    lane -> new FunctionProofCoordinator.Worker<Integer>() {
                        public Integer analyze(Function function, TaskMonitor monitor) {
                            return null;
                        }

                        public void close() {
                            closed.incrementAndGet();
                        }
                    }));
            require(closed.get() > 0, "null result escaped worker cleanup");
        }
    }

    private static void inputSnapshot() throws Exception {
        var input = new ArrayList<>(functions(2));
        var listenerCount = new AtomicInteger();
        var monitor = new TaskMonitorAdapter(true) {
            public void addCancelledListener(CancelledListener listener) {
                listenerCount.incrementAndGet();
                super.addCancelledListener(listener);
            }

            public void removeCancelledListener(CancelledListener listener) {
                super.removeCancelledListener(listener);
                listenerCount.decrementAndGet();
            }
        };
        var results = FunctionProofCoordinator.analyze(input, 1, monitor, lane -> {
            input.clear();
            return new FunctionProofCoordinator.Worker<String>() {
                public String analyze(Function function, TaskMonitor taskMonitor) {
                    return function.getName();
                }

                public void close() {
                }
            };
        });
        require(results.equals(List.of("0", "1")), "input mutation changed planned functions");
        require(listenerCount.get() == 0, "cancellation listener was not removed");
    }

    private static void workerError() throws Exception {
        var closed = new AtomicInteger();
        var failure = new AssertionError("synthetic worker error");
        Throwable thrown = expect(AssertionError.class, () -> FunctionProofCoordinator.analyze(
                functions(2), 2, TaskMonitor.DUMMY,
                lane -> new FunctionProofCoordinator.Worker<Integer>() {
                    public Integer analyze(Function function, TaskMonitor monitor) {
                        throw failure;
                    }

                    public void close() {
                        closed.incrementAndGet();
                    }
                }));
        require(thrown == failure && closed.get() > 0, "worker error lost cleanup or identity");
    }

    private static List<Function> functions(int count) {
        List<Function> functions = new ArrayList<>();
        for (int index = 0; index < count; index++) {
            String name = Integer.toString(index);
            functions.add((Function) Proxy.newProxyInstance(Function.class.getClassLoader(),
                    new Class<?>[] { Function.class }, (proxy, method, args) -> {
                        if (method.getName().equals("getName")) {
                            return name;
                        }
                        throw new AssertionError("unexpected function access: " + method);
                    }));
        }
        return List.copyOf(functions);
    }

    private static void waitForCancellation(TaskMonitor monitor, CountDownLatch started)
            throws Exception {
        var cancelled = new CountDownLatch(1);
        CancelledListener listener = cancelled::countDown;
        monitor.addCancelledListener(listener);
        try {
            started.countDown();
            monitor.checkCancelled();
            await(cancelled);
            monitor.checkCancelled();
        }
        finally {
            monitor.removeCancelledListener(listener);
        }
    }

    private static void await(CountDownLatch latch) throws InterruptedException {
        require(latch.await(5, TimeUnit.SECONDS), "test synchronization timed out");
    }

    private static void awaitUnchecked(CountDownLatch latch) {
        try {
            await(latch);
        }
        catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new AssertionError(failure);
        }
    }

    private static void awaitCleanup(CountDownLatch latch) {
        boolean interrupted = false;
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        try {
            while (true) {
                try {
                    long remaining = deadline - System.nanoTime();
                    require(remaining > 0 && latch.await(remaining, TimeUnit.NANOSECONDS),
                            "cleanup synchronization timed out");
                    return;
                }
                catch (InterruptedException failure) {
                    interrupted = true;
                }
            }
        }
        finally {
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static Throwable expect(Class<? extends Throwable> type, CheckedRunnable action)
            throws Exception {
        try {
            action.run();
        }
        catch (Throwable failure) {
            if (type.isInstance(failure)) {
                return failure;
            }
            throw new AssertionError("expected " + type.getSimpleName(), failure);
        }
        throw new AssertionError("expected " + type.getSimpleName());
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private interface CheckedRunnable {
        void run() throws Exception;
    }
}
