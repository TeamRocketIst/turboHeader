package turboheader.il2cpp.analysis.sharedgeneric;

final class SharedGenericCallProof {
    private static final long MAX_STACK_DISTANCE = 1024 * 1024;

    private SharedGenericCallProof() {
    }

    static boolean accepts(long actualTarget, long expectedTarget,
            long actualMethodInfo, long expectedMethodInfo,
            boolean resultIsStackRelative, long resultOffset, int pointerSize) {
        if (actualTarget != expectedTarget || actualMethodInfo != expectedMethodInfo ||
                !resultIsStackRelative || pointerSize <= 0) {
            return false;
        }
        return resultOffset >= -MAX_STACK_DISTANCE &&
                resultOffset <= MAX_STACK_DISTANCE &&
                Math.floorMod(resultOffset, pointerSize) == 0;
    }
}
