package turboheader.il2cpp;

/**
 * Minimal, allocation-free AArch64 control-flow classifier.
 *
 * <p>This is deliberately not a general instruction decoder. Ghidra/Sleigh remains authoritative
 * for disassembly and decompilation; this classifier exists only for the whole-binary reachability
 * prepass where constructing millions of Sleigh instruction objects is measurably expensive.</p>
 */
final class Aarch64ControlFlowDecoder {
    private static final long REGISTER_BRANCH_CLASS_MASK = 0xfe00_0000L;
    private static final long REGISTER_BRANCH_CLASS = 0xd600_0000L;
    private static final long REGISTER_BRANCH_OPCODE_MASK = 0xffff_fc1fL;
    private static final long INDIRECT_CALL_OPCODE = 0xd63f_0000L;
    private static final long RETURN_OPCODE = 0xd65f_0000L;
    private static final long EXCEPTION_CLASS_MASK = 0xff00_0000L;
    private static final long EXCEPTION_CLASS = 0xd400_0000L;
    private static final long DIRECT_BRANCH_OPCODE_MASK = 0xfc00_0000L;
    private static final long DIRECT_JUMP_OPCODE = 0x1400_0000L;
    private static final long DIRECT_CALL_OPCODE = 0x9400_0000L;
    private static final long CONDITIONAL_BRANCH_MASK = 0xff00_0010L;
    private static final long CONDITIONAL_BRANCH_OPCODE = 0x5400_0000L;
    private static final long COMPARE_BRANCH_MASK = 0x7e00_0000L;
    private static final long COMPARE_BRANCH_OPCODE = 0x3400_0000L;
    private static final long TEST_BRANCH_OPCODE = 0x3600_0000L;
    private static final long LOAD_PAIR_CLASS_MASK = 0x8040_0000L;
    private static final long LOAD_PAIR_CLASS = 0x8040_0000L;

    DecodedInstruction decode(long address, int encoding) {
        long word = Integer.toUnsignedLong(encoding);
        if ((word & REGISTER_BRANCH_CLASS_MASK) == REGISTER_BRANCH_CLASS) {
            long opcode = word & REGISTER_BRANCH_OPCODE_MASK;
            if (opcode == INDIRECT_CALL_OPCODE) {
                return DecodedInstruction.simple(Kind.INDIRECT_CALL);
            }
            if (opcode == RETURN_OPCODE) {
                return DecodedInstruction.simple(Kind.RETURN);
            }
            return DecodedInstruction.simple(Kind.INDIRECT_JUMP);
        }
        if ((word & EXCEPTION_CLASS_MASK) == EXCEPTION_CLASS) {
            return DecodedInstruction.simple(Kind.EXCEPTION);
        }
        long directOpcode = word & DIRECT_BRANCH_OPCODE_MASK;
        if (directOpcode == DIRECT_JUMP_OPCODE) {
            return new DecodedInstruction(Kind.DIRECT_JUMP,
                    relativeTarget(address, word & 0x03ff_ffffL, 26));
        }
        if (directOpcode == DIRECT_CALL_OPCODE) {
            return new DecodedInstruction(Kind.DIRECT_CALL,
                    relativeTarget(address, word & 0x03ff_ffffL, 26));
        }
        if ((word & CONDITIONAL_BRANCH_MASK) == CONDITIONAL_BRANCH_OPCODE ||
                (word & COMPARE_BRANCH_MASK) == COMPARE_BRANCH_OPCODE) {
            return new DecodedInstruction(Kind.CONDITIONAL_BRANCH,
                    relativeTarget(address, (word >>> 5) & 0x7_ffffL, 19));
        }
        if ((word & COMPARE_BRANCH_MASK) == TEST_BRANCH_OPCODE) {
            return new DecodedInstruction(Kind.CONDITIONAL_BRANCH,
                    relativeTarget(address, (word >>> 5) & 0x3fffL, 14));
        }
        return DecodedInstruction.simple(Kind.OTHER);
    }

    boolean isAbiTailTeardown(int encoding) {
        long word = Integer.toUnsignedLong(encoding);
        long addressingMode = (word >>> 23) & 3;
        if ((word & LOAD_PAIR_CLASS_MASK) != LOAD_PAIR_CLASS ||
                (addressingMode != 1 && addressingMode != 3)) {
            return false;
        }
        int baseRegister = (int) ((word >>> 5) & 31);
        int firstDestination = (int) (word & 31);
        int secondDestination = (int) ((word >>> 10) & 31);
        int stackPointer = 31;
        int linkRegister = 30;
        return baseRegister == stackPointer &&
                (firstDestination == linkRegister || secondDestination == linkRegister);
    }

    private long relativeTarget(long address, long immediate, int bits) {
        long signBit = 1L << (bits - 1);
        long signed = (immediate ^ signBit) - signBit;
        return address + (signed << 2);
    }

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
        static DecodedInstruction simple(Kind kind) {
            return new DecodedInstruction(kind, 0);
        }
    }
}
