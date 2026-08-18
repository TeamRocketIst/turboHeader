package turboheader.il2cpp;

/** Conservative structural requirements for propagating a helper identity across one edge. */
final class Il2CppHelperProofPolicy {
    static final int MAX_FORWARDER_INSTRUCTIONS = 4;

    private Il2CppHelperProofPolicy() {
    }

    static boolean provesDirectTailForwarder(int instructionCount, int transferCount,
            boolean expectedTarget, boolean terminalTransfer) {
        return instructionCount > 0 &&
                instructionCount <= MAX_FORWARDER_INSTRUCTIONS &&
                transferCount == 1 && expectedTarget && terminalTransfer;
    }
}
