package turboheader.il2cpp.analysis.sharedgeneric;

public final class SharedGenericCallProofTest {
    public static void main(String[] args) {
        check(SharedGenericCallProof.accepts(
                0x400, 0x400, 0x800, 0x800, true, -72, 8),
                "exact physical call");
        check(SharedGenericCallProof.accepts(
                0x400, 0x400, 0x800, 0x800, true, -4, 4),
                "32-bit result alignment");
        check(SharedGenericCallProof.accepts(
                0x400, 0x400, 0x800, 0x800, true, -29, 1),
                "Boolean result alignment");
        reject(0x404, 0x400, 0x800, 0x800, true, -72, 8,
                "wrong shared body");
        reject(0x400, 0x400, 0x808, 0x800, true, -72, 8,
                "wrong MethodInfo slot");
        reject(0x400, 0x400, 0x800, 0x800, false, -72, 8,
                "non-stack result");
        reject(0x400, 0x400, 0x800, 0x800, true, -6, 4,
                "misaligned result");
        reject(0x400, 0x400, 0x800, 0x800, true, 2 * 1024 * 1024L, 8,
                "unbounded stack result");
        System.out.println("shared generic call proof tests passed");
    }

    private static void reject(long actualTarget, long expectedTarget,
            long actualMethodInfo, long expectedMethodInfo,
            boolean resultIsStackRelative, long resultOffset, int resultAlignment,
            String label) {
        check(!SharedGenericCallProof.accepts(actualTarget, expectedTarget,
                actualMethodInfo, expectedMethodInfo, resultIsStackRelative,
                resultOffset, resultAlignment), label);
    }

    private static void check(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }
}
