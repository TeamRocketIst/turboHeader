package turboheader.il2cpp.analysis.architecture;

public interface ControlFlowDecoder {
    int instructionSize();

    DecodedInstruction decode(long address, int encoding);

    boolean isAbiTailTeardown(int encoding);

    enum Kind {
        OTHER,
        DIRECT_CALL,
        INDIRECT_CALL,
        DIRECT_JUMP,
        INDIRECT_JUMP,
        CONDITIONAL_BRANCH,
        RETURN,
        EXCEPTION
    }

    record DecodedInstruction(Kind kind, long target) {
        public static DecodedInstruction simple(Kind kind) {
            return new DecodedInstruction(kind, 0);
        }
    }
}
