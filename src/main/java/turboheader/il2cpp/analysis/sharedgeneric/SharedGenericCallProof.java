package turboheader.il2cpp.analysis.sharedgeneric;

final class SharedGenericCallProof {
    private static final long MAX_STACK_DISTANCE = 1024 * 1024;

    private SharedGenericCallProof() {
    }

    static boolean accepts(long actualTarget, long expectedTarget,
            long actualMethodInfo, long expectedMethodInfo,
            boolean resultIsStackRelative, long resultOffset, int resultAlignment) {
        if (actualTarget != expectedTarget || actualMethodInfo != expectedMethodInfo ||
                !resultIsStackRelative || resultAlignment <= 0) {
            return false;
        }
        return resultOffset >= -MAX_STACK_DISTANCE &&
                resultOffset <= MAX_STACK_DISTANCE &&
                Math.floorMod(resultOffset, resultAlignment) == 0;
    }
}
