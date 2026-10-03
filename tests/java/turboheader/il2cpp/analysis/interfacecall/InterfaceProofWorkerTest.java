package turboheader.il2cpp.analysis.interfacecall;

import java.util.List;
import java.util.Map;

import ghidra.util.task.TaskMonitor;

public final class InterfaceProofWorkerTest {
    public static void main(String[] args) throws Exception {
        var timing = new Il2CppInterfaceCallAnalyzer.PhaseTiming(1, 2, 100, 10, 30);
        require(timing.wallNanos() == 33 && timing.measuredNanos() == 113,
                "wall time includes overlapping work");
        var stats = new Il2CppInterfaceCallAnalyzer.AnalysisStats(
                Il2CppInterfaceCallAnalyzer.Outcome.COMPLETE,
                0, 0, 0, 0, 0, 0, 0, 0, InterfaceCallRejectionCounts.none(),
                List.of(), List.of(), timing, List.of(), 40);
        require(stats.elapsedNanos() < timing.measuredNanos(),
                "aggregate work was treated as elapsed time");
        expect(IllegalArgumentException.class,
                () -> new Il2CppInterfaceCallAnalyzer.AnalysisStats(
                        Il2CppInterfaceCallAnalyzer.Outcome.COMPLETE,
                        0, 0, 0, 0, 0, 0, 0, 0, InterfaceCallRejectionCounts.none(),
                        List.of(), List.of(), timing, List.of(), 32));
        var sequential = new Il2CppInterfaceCallAnalyzer.PhaseTiming(1, 2, 10, 20);
        require(sequential.wallNanos() == 33 && sequential.measuredNanos() == 33,
                "sequential timing constructor differs");
        require(Il2CppInterfaceCallAnalyzer.PhaseTiming.empty().wallNanos() == 0,
                "empty timing differs");
        expect(IllegalArgumentException.class,
                () -> new Il2CppInterfaceCallAnalyzer.PhaseTiming(0, 0, 0, 0, -1));
        expect(IllegalArgumentException.class,
                () -> new InterfaceProofWorker.FunctionResult(null, -1, 0));
        expect(IllegalArgumentException.class,
                () -> new InterfaceProofWorker.FunctionResult(null, 1, 1));
        var failed = new InterfaceProofWorker.FunctionResult(null, 1, 0);
        require(failed.resolved() == null && failed.resolutionNanos() == 0,
                "failed decompilation acquired a proof result");
        var resolved = new GhidraPcodeInterfaceCallResolver.Result(0, 0, List.of());
        require(new InterfaceProofWorker.FunctionResult(resolved, 1, 2).resolved() == resolved,
                "resolved function result changed");
        expect(ArithmeticException.class, () -> new Il2CppInterfaceCallAnalyzer.PhaseTiming(
                0, 0, Long.MAX_VALUE, 1));
        expect(ArithmeticException.class, () -> new Il2CppInterfaceCallAnalyzer.PhaseTiming(
                Long.MAX_VALUE, 1, 0, 0, 0).wallNanos());
        expect(ArithmeticException.class, () -> new Il2CppInterfaceCallAnalyzer.PhaseTiming(
                0, 0, Long.MAX_VALUE, 1, 0).measuredNanos());
        for (int workers : new int[] { -1, 0, 9, Integer.MAX_VALUE }) {
            expect(IllegalArgumentException.class, () -> Il2CppInterfaceCallAnalyzer.analyze(
                    null, List.of(), Map.of(), workers, TaskMonitor.DUMMY));
        }
        System.out.println("InterfaceProofWorkerTest: result, timing and worker validation passed");
    }

    private static void expect(Class<? extends Throwable> type, CheckedRunnable action)
            throws Exception {
        try {
            action.run();
        }
        catch (Throwable failure) {
            if (type.isInstance(failure)) {
                return;
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
