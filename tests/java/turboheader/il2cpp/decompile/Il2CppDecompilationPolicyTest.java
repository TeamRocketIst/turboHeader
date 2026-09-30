package turboheader.il2cpp.decompile;

public final class Il2CppDecompilationPolicyTest {
    public static void main(String[] args) {
        for (int jobs = 1; jobs <= 12; jobs++) {
            require(Il2CppDecompilationPolicy.delegateWorkers(jobs) == Math.min(jobs, 4),
                    "delegate worker count differs for jobs=" + jobs);
        }
        for (int jobs : new int[] { Integer.MIN_VALUE, -1, 0, 13, Integer.MAX_VALUE }) {
            try {
                Il2CppDecompilationPolicy.delegateWorkers(jobs);
                throw new AssertionError("invalid job count accepted: " + jobs);
            }
            catch (IllegalArgumentException expected) {
            }
        }
        System.out.println("Il2CppDecompilationPolicyTest: 17 cases passed");
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
