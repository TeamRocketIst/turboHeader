package turboheader.il2cpp.decompile;

import java.util.function.IntUnaryOperator;

public final class Il2CppDecompilationPolicyTest {
    public static void main(String[] args) {
        for (int jobs = 1; jobs <= 12; jobs++) {
            require(Il2CppDecompilationPolicy.proofWorkers(jobs) == Math.min(jobs, 8),
                    "proof worker count differs for jobs=" + jobs);
            require(Il2CppDecompilationPolicy.delegateWorkers(jobs) == Math.min(jobs, 8),
                    "delegate worker count differs for jobs=" + jobs);
        }
        for (int jobs : new int[] { Integer.MIN_VALUE, -1, 0, 13, Integer.MAX_VALUE }) {
            reject(jobs, Il2CppDecompilationPolicy::proofWorkers);
            reject(jobs, Il2CppDecompilationPolicy::delegateWorkers);
        }
        System.out.println("Il2CppDecompilationPolicyTest: 34 cases passed");
    }

    private static void reject(int jobs, IntUnaryOperator policy) {
        try {
            policy.applyAsInt(jobs);
            throw new AssertionError("invalid job count accepted: " + jobs);
        }
        catch (IllegalArgumentException expected) {
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
