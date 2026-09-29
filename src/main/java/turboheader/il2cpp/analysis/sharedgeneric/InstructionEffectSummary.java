package turboheader.il2cpp.analysis.sharedgeneric;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public final class InstructionEffectSummary {
    private static final int MAX_OPERATIONS = 256;
    private static final int MAX_VALUE_BYTES = 128;

    private InstructionEffectSummary() {
    }

    public static Optional<List<Varnode>> localBranchWrites(PcodeOp[] operations, Address fallthrough) {
        if (fallthrough == null || operations == null || operations.length == 0 ||
                operations.length > MAX_OPERATIONS) return Optional.empty();
        var writes = new LinkedHashSet<Varnode>();
        boolean branched = false;
        for (int index = 0; index < operations.length; index++) {
            PcodeOp operation = operations[index];
            if (operation == null) return Optional.empty();
            int opcode = operation.getOpcode();
            if (opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH) {
                int inputs = opcode == PcodeOp.BRANCH ? 1 : 2;
                if (operation.getOutput() != null || operation.getNumInputs() != inputs ||
                        !localTarget(operation.getInput(0), index, operations.length, fallthrough)) {
                    return Optional.empty();
                }
                if (inputs == 2 && (!localValue(operation.getInput(1)) || operation.getInput(1).getSize() != 1)) {
                    return Optional.empty();
                }
                branched = true;
                continue;
            }
            int inputs = switch (opcode) {
                case PcodeOp.COPY, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT,
                        PcodeOp.BOOL_NEGATE, PcodeOp.FLOAT_NAN, PcodeOp.FLOAT_INT2FLOAT -> 1;
                case PcodeOp.BOOL_AND, PcodeOp.BOOL_OR, PcodeOp.BOOL_XOR,
                        PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL, PcodeOp.INT_LESS,
                        PcodeOp.INT_SLESS, PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESSEQUAL,
                        PcodeOp.FLOAT_EQUAL, PcodeOp.FLOAT_LESS, PcodeOp.FLOAT_LESSEQUAL -> 2;
                default -> -1;
            };
            Varnode output = operation.getOutput();
            if (operation.getNumInputs() != inputs || !localValue(output) || output.isConstant()) {
                return Optional.empty();
            }
            for (int input = 0; input < inputs; input++) {
                if (!localValue(operation.getInput(input))) return Optional.empty();
            }
            if (output.isRegister()) writes.add(output);
        }
        return branched ? Optional.of(List.copyOf(writes)) : Optional.empty();
    }

    static boolean hasBranch(PcodeOp[] operations) {
        for (PcodeOp operation : operations) {
            if (operation.getOpcode() == PcodeOp.BRANCH || operation.getOpcode() == PcodeOp.CBRANCH) return true;
        }
        return false;
    }

    private static boolean localTarget(Varnode target, int index, int length, Address fallthrough) {
        if (target == null) return false;
        if (target.isConstant()) {
            long delta = target.getOffset();
            return delta > 0 && delta < length - index;
        }
        return target.isAddress() && target.getAddress().equals(fallthrough);
    }

    private static boolean localValue(Varnode value) {
        return value != null && value.getSize() > 0 && value.getSize() <= MAX_VALUE_BYTES &&
                (value.isRegister() || value.isUnique() || value.isConstant());
    }
}
