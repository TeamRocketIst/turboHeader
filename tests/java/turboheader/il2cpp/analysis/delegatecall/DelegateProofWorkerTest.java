package turboheader.il2cpp.analysis.delegatecall;

import java.util.List;

public final class DelegateProofWorkerTest {
    public static void main(String[] args) throws Exception {
        var timing = new Il2CppDelegateCallAnalyzer.PhaseTiming(1, 2, 100, 10, 30);
        require(timing.wallNanos() == 33 && timing.measuredNanos() == 113,
                "wall time includes overlapping work");
        new Il2CppDelegateCallAnalyzer.AnalysisStats(Il2CppDelegateCallAnalyzer.Outcome.COMPLETE,
                0, 0, 0, 0, 0, 0, 0, DelegateCallRejectionCounts.none(),
                List.of(), List.of(), timing, 40);
        expect(IllegalArgumentException.class,
                () -> new Il2CppDelegateCallAnalyzer.PhaseTiming(0, 0, 0, 0, -1));
        expect(IllegalArgumentException.class,
                () -> new DelegateProofWorker.FunctionResult(null, -1, 0));
        expect(IllegalArgumentException.class,
                () -> new DelegateProofWorker.FunctionResult(null, 1, 1));
        expect(ArithmeticException.class,
                () -> new Il2CppDelegateCallAnalyzer.PhaseTiming(
                        Long.MAX_VALUE, 1, 0, 0, 0).wallNanos());
        System.out.println("DelegateProofWorkerTest: timing validation passed");
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
