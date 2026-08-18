package turboheader.il2cpp;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import generic.cache.BasicFactory;
import generic.cache.CachingPool;
import generic.concurrent.GThreadPool;
import generic.concurrent.QCallback;
import generic.concurrent.QResult;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.util.DecompilerConcurrentQ;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Decompiles a prepared, read-only function list with a bounded private Ghidra worker pool.
 *
 * <p>The caller must finish all {@link Program} mutations and auto-analysis before invoking this
 * service. Each active job borrows a distinct {@link DecompInterface}, which means a distinct
 * native decompiler process. Results are returned in submission order even though workers finish
 * in runtime order.</p>
 */
public final class Il2CppDecompilerService {
    private static final AtomicInteger POOL_SEQUENCE = new AtomicInteger();

    private Il2CppDecompilerService() {
    }

    /**
     * Decompile prepared functions, retrying every failed first attempt once with a fresh pool.
     *
     * @param program stable program that workers may read
     * @param functions functions in deterministic output order; duplicate entries remain duplicate
     * @param workerCount maximum simultaneous native decompiler processes
     * @param timeoutSeconds timeout for each decompiler invocation
     * @param taskMonitor cancellation/progress monitor
     * @return immutable batch result in the same order as {@code functions}
     * @throws Exception if queue creation, cancellation, or worker infrastructure fails
     */
    public static BatchResult decompileFunctions(Program program, List<Function> functions,
            int workerCount, int timeoutSeconds, TaskMonitor taskMonitor) throws Exception {
        if (program == null) {
            throw new IllegalArgumentException("program is required");
        }
        if (functions == null) {
            throw new IllegalArgumentException("functions are required");
        }
        if (workerCount < 1) {
            throw new IllegalArgumentException("workerCount must be at least 1");
        }
        if (timeoutSeconds < 1) {
            throw new IllegalArgumentException("timeoutSeconds must be at least 1");
        }

        TaskMonitor monitor = taskMonitor == null ? TaskMonitor.DUMMY : taskMonitor;
        long totalStarted = System.nanoTime();

        List<DecompileJob> initialJobs = new ArrayList<>(functions.size());
        for (int index = 0; index < functions.size(); index++) {
            Function function = functions.get(index);
            if (function == null) {
                throw new IllegalArgumentException("function at index " + index + " is null");
            }
            initialJobs.add(new DecompileJob(index, function));
        }

        PassResult firstPass = runPass(program, initialJobs, workerCount, timeoutSeconds, monitor,
                "initial");
        monitor.checkCancelled();
        Map<Integer, Attempt> firstByIndex = firstPass.attempts();

        List<DecompileJob> retryJobs = new ArrayList<>();
        for (DecompileJob job : initialJobs) {
            Attempt attempt = firstByIndex.get(job.index());
            if (attempt == null || !attempt.completed()) {
                retryJobs.add(job);
            }
        }

        PassResult retryPass = retryJobs.isEmpty()
                ? PassResult.empty()
                : runPass(program, retryJobs, workerCount, timeoutSeconds, monitor, "retry");
        monitor.checkCancelled();

        List<FunctionResult> ordered = new ArrayList<>(functions.size());
        int recovered = 0;
        for (DecompileJob job : initialJobs) {
            Attempt first = firstByIndex.get(job.index());
            Attempt retry = retryPass.attempts().get(job.index());
            Attempt selected = retry == null ? first : retry;
            boolean retryAttempted = first == null || !first.completed();
            if (selected == null) {
                selected = Attempt.failure(job.function(), "No decompiler result was returned", 0);
            }
            boolean recoveredOnRetry = retry != null && retry.completed();
            if (recoveredOnRetry) {
                recovered++;
            }
            long elapsedNanos = (first == null ? 0 : first.elapsedNanos()) +
                    (retry == null ? 0 : retry.elapsedNanos());
            ordered.add(new FunctionResult(job.index(), job.function().getEntryPoint(),
                    selected.completed(), selected.cCode(), selected.errorMessage(), retryAttempted,
                    recoveredOnRetry, elapsedNanos));
        }

        return new BatchResult(ordered, workerCount, retryJobs.size(), recovered,
                firstPass.elapsedNanos(), retryPass.elapsedNanos(),
                System.nanoTime() - totalStarted);
    }

    private static PassResult runPass(Program program, List<DecompileJob> jobs, int workerCount,
            int timeoutSeconds, TaskMonitor monitor, String passName) throws Exception {
        if (jobs.isEmpty()) {
            return PassResult.empty();
        }

        if (workerCount > 1) {
            return runDeterministicLanePass(program, jobs, workerCount, timeoutSeconds, monitor,
                    passName);
        }

        return runQueuedPass(program, jobs, workerCount, timeoutSeconds, monitor, passName);
    }

    private static PassResult runQueuedPass(Program program, List<DecompileJob> jobs,
            int workerCount, int timeoutSeconds, TaskMonitor monitor, String passName)
            throws Exception {

        String poolName = "TurboHeader Decompiler " + POOL_SEQUENCE.incrementAndGet();
        GThreadPool threadPool = GThreadPool.getPrivateThreadPool(poolName);
        threadPool.setMaxThreadCount(workerCount);
        CachingPool<DecompInterface> decompilers = new CachingPool<>(
                new DecompilerFactory(program));
        AtomicInteger completedJobs = new AtomicInteger();
        int totalJobs = jobs.size();

        QCallback<DecompileJob, Attempt> callback = (job, jobMonitor) -> {
            long started = System.nanoTime();
            DecompInterface decompiler = null;
            Attempt attempt;
            try {
                jobMonitor.checkCancelled();
                decompiler = decompilers.get();
                DecompileResults results = decompiler.decompileFunction(job.function(),
                        timeoutSeconds, jobMonitor);
                attempt = toAttempt(job.function(), results, System.nanoTime() - started);
            }
            catch (CancelledException error) {
                throw error;
            }
            catch (Exception error) {
                attempt = Attempt.failure(job.function(), safeMessage(error),
                        System.nanoTime() - started);
            }
            finally {
                if (decompiler != null) {
                    decompilers.release(decompiler);
                }
            }

            int done = completedJobs.incrementAndGet();
            System.out.println(String.format(Locale.ROOT,
                    "TurboHeader decompile %s: %d/%d %s @ %s (%s, %.3fs)", passName,
                    done, totalJobs, job.function().getName(), job.function().getEntryPoint(),
                    attempt.completed() ? "ok" : "failed", attempt.elapsedSeconds()));
            return attempt;
        };

        DecompilerConcurrentQ<DecompileJob, Attempt> queue =
                new DecompilerConcurrentQ<>(callback, threadPool, true, monitor);
        long started = System.nanoTime();
        Collection<QResult<DecompileJob, Attempt>> queueResults;
        try {
            monitor.initialize(jobs.size());
            queue.addAll(jobs);
            queueResults = queue.waitForResults();
        }
        finally {
            queue.dispose();
            decompilers.dispose();
        }

        Map<Integer, Attempt> attempts = new LinkedHashMap<>();
        for (QResult<DecompileJob, Attempt> queueResult : queueResults) {
            DecompileJob job = queueResult.getItem();
            Attempt attempt;
            try {
                attempt = queueResult.getResult();
            }
            catch (Exception error) {
                attempt = Attempt.failure(job.function(), safeMessage(error), 0);
            }
            attempts.put(job.index(), attempt);
        }
        return new PassResult(attempts, System.nanoTime() - started);
    }

    private static PassResult runDeterministicLanePass(Program program,
            List<DecompileJob> jobs, int workerCount, int timeoutSeconds, TaskMonitor monitor,
            String passName) throws Exception {
        List<List<DecompileJob>> jobsByLane = new ArrayList<>(workerCount);
        for (int laneIndex = 0; laneIndex < workerCount; laneIndex++) {
            jobsByLane.add(new ArrayList<>());
        }
        for (DecompileJob job : jobs) {
            jobsByLane.get(Math.floorMod(job.index(), workerCount)).add(job);
        }

        List<LaneJob> lanes = new ArrayList<>(workerCount);
        for (int laneIndex = 0; laneIndex < workerCount; laneIndex++) {
            List<DecompileJob> laneJobs = jobsByLane.get(laneIndex);
            if (!laneJobs.isEmpty()) {
                lanes.add(new LaneJob(laneIndex, List.copyOf(laneJobs)));
            }
        }

        String poolName = "TurboHeader Deterministic Lanes " +
                POOL_SEQUENCE.incrementAndGet();
        GThreadPool threadPool = GThreadPool.getPrivateThreadPool(poolName);
        threadPool.setMaxThreadCount(workerCount);
        AtomicInteger completedJobs = new AtomicInteger();
        int totalJobs = jobs.size();

        QCallback<LaneJob, LaneResult> callback = (lane, laneMonitor) -> {
            Map<Integer, Attempt> laneAttempts = new LinkedHashMap<>();
            DecompInterface decompiler = new DecompInterface();
            try {
                if (!decompiler.openProgram(program)) {
                    throw new IllegalStateException(
                            "Ghidra decompiler did not open the program for lane " +
                                    lane.laneIndex());
                }

                for (DecompileJob job : lane.jobs()) {
                    laneMonitor.checkCancelled();
                    long functionStarted = System.nanoTime();
                    Attempt attempt;
                    try {
                        DecompileResults results = decompiler.decompileFunction(job.function(),
                                timeoutSeconds, laneMonitor);
                        attempt = toAttempt(job.function(), results,
                                System.nanoTime() - functionStarted);
                    }
                    catch (Exception error) {
                        attempt = Attempt.failure(job.function(), safeMessage(error),
                                System.nanoTime() - functionStarted);
                    }
                    laneAttempts.put(job.index(), attempt);

                    int done = completedJobs.incrementAndGet();
                    System.out.println(String.format(Locale.ROOT,
                            "TurboHeader decompile %s lane=%d: %d/%d %s @ %s (%s, %.3fs)",
                            passName, lane.laneIndex(), done, totalJobs,
                            job.function().getName(), job.function().getEntryPoint(),
                            attempt.completed() ? "ok" : "failed", attempt.elapsedSeconds()));
                }
            }
            finally {
                decompiler.dispose();
            }
            return new LaneResult(lane.laneIndex(), laneAttempts);
        };

        DecompilerConcurrentQ<LaneJob, LaneResult> queue =
                new DecompilerConcurrentQ<>(callback, threadPool, true, monitor);
        long started = System.nanoTime();
        Collection<QResult<LaneJob, LaneResult>> queueResults;
        try {
            // ConcurrentQ advances once per queued lane. Per-function progress is
            // reported explicitly by completedJobs in the callback above.
            monitor.initialize(lanes.size());
            queue.addAll(lanes);
            queueResults = queue.waitForResults();
        }
        finally {
            queue.dispose();
        }

        Map<Integer, Attempt> attempts = new LinkedHashMap<>();
        for (QResult<LaneJob, LaneResult> queueResult : queueResults) {
            LaneJob lane = queueResult.getItem();
            try {
                attempts.putAll(queueResult.getResult().attempts());
            }
            catch (Exception error) {
                String message = "Lane " + lane.laneIndex() + " failed: " +
                        safeMessage(error);
                for (DecompileJob job : lane.jobs()) {
                    attempts.put(job.index(), Attempt.failure(job.function(), message, 0));
                }
            }
        }
        return new PassResult(attempts, System.nanoTime() - started);
    }

    private static Attempt toAttempt(Function function, DecompileResults results,
            long elapsedNanos) {
        if (results == null) {
            return Attempt.failure(function, "Decompiler returned no result", elapsedNanos);
        }
        if (!results.decompileCompleted()) {
            return Attempt.failure(function, results.getErrorMessage(), elapsedNanos);
        }
        DecompiledFunction decompiled = results.getDecompiledFunction();
        if (decompiled == null || decompiled.getC() == null) {
            return Attempt.failure(function, "Decompiler completed without C output", elapsedNanos);
        }
        return new Attempt(function, true, decompiled.getC(), results.getErrorMessage(),
                elapsedNanos);
    }

    private static String safeMessage(Throwable error) {
        if (error == null) {
            return "Unknown decompiler failure";
        }
        String message = error.getMessage();
        return message == null || message.isBlank() ? error.getClass().getName() : message;
    }

    private record DecompileJob(int index, Function function) {
    }

    private record LaneJob(int laneIndex, List<DecompileJob> jobs) {
    }

    private record LaneResult(int laneIndex, Map<Integer, Attempt> attempts) {
    }

    private record Attempt(Function function, boolean completed, String cCode,
            String errorMessage, long elapsedNanos) {
        static Attempt failure(Function function, String message, long elapsedNanos) {
            String error = message == null || message.isBlank()
                    ? "Decompiler did not complete"
                    : message;
            return new Attempt(function, false, null, error, elapsedNanos);
        }

        double elapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }

    private record PassResult(Map<Integer, Attempt> attempts, long elapsedNanos) {
        PassResult {
            attempts = Collections.unmodifiableMap(new LinkedHashMap<>(attempts));
        }

        static PassResult empty() {
            return new PassResult(Map.of(), 0);
        }
    }

    private static final class DecompilerFactory implements BasicFactory<DecompInterface> {
        private final Program program;

        DecompilerFactory(Program program) {
            this.program = program;
        }

        @Override
        public DecompInterface create() {
            DecompInterface decompiler = new DecompInterface();
            if (!decompiler.openProgram(program)) {
                decompiler.dispose();
                throw new IllegalStateException("Ghidra decompiler did not open the program");
            }
            return decompiler;
        }

        @Override
        public void dispose(DecompInterface decompiler) {
            decompiler.dispose();
        }
    }

    /** Immutable result for one submitted function occurrence. */
    public static final class FunctionResult {
        private final int index;
        private final Address entryPoint;
        private final boolean completed;
        private final String cCode;
        private final String errorMessage;
        private final boolean retried;
        private final boolean recoveredOnRetry;
        private final long elapsedNanos;

        FunctionResult(int index, Address entryPoint, boolean completed, String cCode,
                String errorMessage, boolean retried, boolean recoveredOnRetry,
                long elapsedNanos) {
            this.index = index;
            this.entryPoint = entryPoint;
            this.completed = completed;
            this.cCode = cCode;
            this.errorMessage = errorMessage;
            this.retried = retried;
            this.recoveredOnRetry = recoveredOnRetry;
            this.elapsedNanos = elapsedNanos;
        }

        public int getIndex() {
            return index;
        }

        public Address getEntryPoint() {
            return entryPoint;
        }

        public boolean isCompleted() {
            return completed;
        }

        public String getCCode() {
            return cCode;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public boolean isRetried() {
            return retried;
        }

        public boolean isRecoveredOnRetry() {
            return recoveredOnRetry;
        }

        public long getElapsedNanos() {
            return elapsedNanos;
        }

        public double getElapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }

    /** Immutable aggregate for a complete invocation. */
    public static final class BatchResult {
        private final List<FunctionResult> results;
        private final int workerCount;
        private final int retryCount;
        private final int recoveredCount;
        private final long firstPassNanos;
        private final long retryPassNanos;
        private final long totalNanos;

        BatchResult(List<FunctionResult> results, int workerCount, int retryCount,
                int recoveredCount, long firstPassNanos, long retryPassNanos, long totalNanos) {
            this.results = Collections.unmodifiableList(new ArrayList<>(results));
            this.workerCount = workerCount;
            this.retryCount = retryCount;
            this.recoveredCount = recoveredCount;
            this.firstPassNanos = firstPassNanos;
            this.retryPassNanos = retryPassNanos;
            this.totalNanos = totalNanos;
        }

        public List<FunctionResult> getResults() {
            return results;
        }

        public int getWorkerCount() {
            return workerCount;
        }

        public int getRetryCount() {
            return retryCount;
        }

        public int getRecoveredCount() {
            return recoveredCount;
        }

        public double getFirstPassSeconds() {
            return firstPassNanos / 1_000_000_000.0;
        }

        public double getRetryPassSeconds() {
            return retryPassNanos / 1_000_000_000.0;
        }

        public double getTotalSeconds() {
            return totalNanos / 1_000_000_000.0;
        }
    }
}
