package turboheader.il2cpp.analysis.delegatecall;

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

public final class DelegateProofCoordinatorTest {
    public static void main(String[] args) throws Exception {
        orderedLanes(1, 12);
        orderedLanes(2, 12);
        orderedLanes(4, 12);
        orderedLanes(4, 2);
        invalidRequests();
        failureDrainsWorkers(true);
        failureDrainsWorkers(false);
        cancellationDrainsWorkers(false);
        cancellationDrainsWorkers(true);
        closeFailure();
        overlappingTimings();
        System.out.println("DelegateProofCoordinatorTest: 11 cases passed");
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
        var results = DelegateProofCoordinator.analyze(functions, workers, TaskMonitor.DUMMY,
                lane -> {
                    opened.incrementAndGet();
                    Thread owner = Thread.currentThread();
                    return new DelegateProofCoordinator.Worker() {
                        private int next = lane;

                        public DelegateProofCoordinator.FunctionResult analyze(
                                Function function, TaskMonitor monitor) {
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
        DelegateProofCoordinator.WorkerFactory forbidden = lane -> {
            throw new AssertionError("unexpected worker");
        };
        for (int workers : new int[] { -1, 0, 5, Integer.MAX_VALUE }) {
            expect(IllegalArgumentException.class, () -> DelegateProofCoordinator.analyze(
                    functions(1), workers, TaskMonitor.DUMMY, forbidden));
        }
        require(DelegateProofCoordinator.analyze(List.of(), 4, TaskMonitor.DUMMY,
                forbidden).isEmpty(), "empty input opened workers");
        var cancelled = new TaskMonitorAdapter(true);
        cancelled.cancel();
        expect(CancelledException.class, () -> DelegateProofCoordinator.analyze(
                functions(1), 1, cancelled, forbidden));
        var cancelledOnRegistration = new TaskMonitorAdapter(true) {
            public void addCancelledListener(CancelledListener listener) {
                cancel();
                super.addCancelledListener(listener);
            }
        };
        expect(CancelledException.class, () -> DelegateProofCoordinator.analyze(
                functions(1), 1, cancelledOnRegistration, forbidden));
    }

    private static void failureDrainsWorkers(boolean setupFailure) throws Exception {
        var peerStarted = new CountDownLatch(1);
        var closed = new AtomicInteger();
        var parent = new TaskMonitorAdapter(true);
        var failure = new IllegalStateException("synthetic failure");
        Throwable thrown = expect(IllegalStateException.class,
                () -> DelegateProofCoordinator.analyze(functions(2), 2, parent, lane -> {
                    if (lane == 0 && setupFailure) {
                        await(peerStarted);
                        throw failure;
                    }
                    return new DelegateProofCoordinator.Worker() {
                        public DelegateProofCoordinator.FunctionResult analyze(
                                Function function, TaskMonitor monitor) throws Exception {
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
        require(closed.get() == (setupFailure ? 1 : 2), "workers escaped failure cleanup");
        require(!parent.isCancelled(), "internal failure cancelled the caller's monitor");
    }

    private static void cancellationDrainsWorkers(boolean interrupt) throws Exception {
        var started = new CountDownLatch(2);
        var closing = new CountDownLatch(2);
        var releaseClose = new CountDownLatch(1);
        var closed = new AtomicInteger();
        var parent = new TaskMonitorAdapter(true);
        var failure = new AtomicReference<Throwable>();
        var interrupted = new AtomicReference<Boolean>(false);
        Thread caller = new Thread(() -> {
            try {
                DelegateProofCoordinator.analyze(functions(2), 2, parent, lane ->
                        new DelegateProofCoordinator.Worker() {
                            public DelegateProofCoordinator.FunctionResult analyze(
                                    Function function, TaskMonitor monitor) throws Exception {
                                waitForCancellation(monitor, started);
                                return result(lane);
                            }

                            public void close() {
                                closing.countDown();
                                // Native cleanup must finish even after Future.cancel(true).
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
        }, "delegate-test-caller");
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
            require(closed.get() == 2, "cancelled workers were not closed");
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

    private static void closeFailure() throws Exception {
        var closed = new AtomicInteger();
        var started = new CountDownLatch(2);
        expect(IllegalStateException.class, () -> DelegateProofCoordinator.analyze(
                functions(2), 2, TaskMonitor.DUMMY, lane -> new DelegateProofCoordinator.Worker() {
                    public DelegateProofCoordinator.FunctionResult analyze(
                            Function function, TaskMonitor monitor) throws Exception {
                        started.countDown();
                        await(started);
                        return result(lane);
                    }

                    public void close() {
                        closed.incrementAndGet();
                        throw new IllegalStateException("synthetic close failure");
                    }
                }));
        require(closed.get() == 2, "failing workers were not closed");
    }

    private static void overlappingTimings() throws Exception {
        var timing = new Il2CppDelegateCallAnalyzer.PhaseTiming(1, 2, 100, 10, 30);
        require(timing.wallNanos() == 33 && timing.measuredNanos() == 113,
                "wall time includes overlapping work");
        new Il2CppDelegateCallAnalyzer.AnalysisStats(Il2CppDelegateCallAnalyzer.Outcome.COMPLETE,
                0, 0, 0, 0, 0, 0, 0, DelegateCallRejectionCounts.none(),
                List.of(), List.of(), timing, 40);
        expect(IllegalArgumentException.class,
                () -> new Il2CppDelegateCallAnalyzer.PhaseTiming(0, 0, 0, 0, -1));
        expect(IllegalArgumentException.class,
                () -> new DelegateProofCoordinator.FunctionResult(null, -1, 0));
        expect(IllegalArgumentException.class,
                () -> new DelegateProofCoordinator.FunctionResult(null, 1, 1));
        expect(ArithmeticException.class,
                () -> new Il2CppDelegateCallAnalyzer.PhaseTiming(
                        Long.MAX_VALUE, 1, 0, 0, 0).wallNanos());
    }

    private static DelegateProofCoordinator.FunctionResult result(int index) {
        var resolved = index == 3 ? null :
                new GhidraPcodeDelegateCallResolver.Result(index, 0, 0, List.of());
        return new DelegateProofCoordinator.FunctionResult(resolved, index, 0);
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
