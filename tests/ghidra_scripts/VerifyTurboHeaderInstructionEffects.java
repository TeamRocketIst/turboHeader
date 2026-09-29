// @category Test

import java.util.Arrays;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import turboheader.il2cpp.analysis.sharedgeneric.InstructionEffectSummary;

public class VerifyTurboHeaderInstructionEffects extends GhidraScript {
    private Address entry;
    private Address next;
    private Varnode flag;
    private Varnode first;
    private Varnode second;
    private int checks;

    @Override
    protected void run() throws Exception {
        entry = toAddr(0x1000);
        next = entry.add(4);
        flag = new Varnode(currentProgram.getAddressFactory().getUniqueSpace().getAddress(0x100), 1);
        first = register("x8");
        second = register("x9");
        PcodeOp copyFirst = op(PcodeOp.COPY, first, second);
        PcodeOp copySecond = op(PcodeOp.COPY, second, first);
        PcodeOp local = op(PcodeOp.CBRANCH, null, constant(2), flag);
        PcodeOp[] valid = { local, copyFirst, copySecond };
        var writes = InstructionEffectSummary.localBranchWrites(valid, next).orElseThrow();
        require(writes.equals(List.of(first, second)), "both alternatives must contribute writes");
        require(InstructionEffectSummary.localBranchWrites(new PcodeOp[] {
                op(PcodeOp.CBRANCH, null, new Varnode(next, 8), flag), copyFirst }, next)
                .orElseThrow().equals(List.of(first)), "fallthrough exit was rejected");
        require(InstructionEffectSummary.localBranchWrites(new PcodeOp[] {
                op(PcodeOp.BRANCH, null, constant(1)), copyFirst }, next).isPresent(), "forward branch rejected");
        var alias = register("w8");
        var aliasWrites = InstructionEffectSummary.localBranchWrites(new PcodeOp[] {
                op(PcodeOp.CBRANCH, null, new Varnode(next, 8), flag),
                op(PcodeOp.COPY, alias, register("w9")) }, next).orElseThrow();
        require(aliasWrites.stream().anyMatch(first::intersects), "subregister write missed its parent");

        for (long target : new long[] { 0, -1, 3, Long.MAX_VALUE }) {
            rejected(new PcodeOp[] { op(PcodeOp.CBRANCH, null, constant(target), flag), copyFirst, copySecond });
        }
        rejected(new PcodeOp[] { op(PcodeOp.CBRANCH, null, new Varnode(next.add(4), 8), flag), copyFirst });
        rejected(new PcodeOp[] { op(PcodeOp.CBRANCH, null, first, flag), copyFirst });
        rejected(new PcodeOp[] { op(PcodeOp.CBRANCH, null, constant(1)), copyFirst });
        rejected(new PcodeOp[] { op(PcodeOp.CBRANCH, null, constant(1), first), copyFirst });
        rejected(new PcodeOp[] { op(PcodeOp.CBRANCH, first, constant(1), flag), copyFirst });
        for (int opcode : new int[] { PcodeOp.LOAD, PcodeOp.STORE, PcodeOp.CALL, PcodeOp.CALLIND,
                PcodeOp.CALLOTHER, PcodeOp.BRANCHIND, PcodeOp.RETURN, PcodeOp.UNIMPLEMENTED }) {
            rejected(new PcodeOp[] { local, op(opcode, null), copyFirst });
        }
        rejected(new PcodeOp[] { local, op(PcodeOp.COPY, new Varnode(entry, 8), first), copyFirst });
        rejected(new PcodeOp[] { local, op(PcodeOp.COPY, first, new Varnode(entry, 8)), copyFirst });
        rejected(new PcodeOp[] { local, op(PcodeOp.COPY, first), copyFirst });
        rejected(new PcodeOp[] { local, null, copyFirst });
        rejected(new PcodeOp[] { copyFirst });
        rejected(new PcodeOp[0]);
        rejected(null);
        require(InstructionEffectSummary.localBranchWrites(valid, null).isEmpty(), "missing exit accepted");
        PcodeOp[] oversized = new PcodeOp[257];
        Arrays.fill(oversized, copyFirst);
        oversized[0] = local;
        rejected(oversized);
        println("TurboHeader instruction effects verification passed: " + checks + " checks");
    }

    private void rejected(PcodeOp[] operations) {
        require(InstructionEffectSummary.localBranchWrites(operations, next).isEmpty(), "unsafe effects accepted");
    }

    private PcodeOp op(int opcode, Varnode output, Varnode... inputs) {
        return new PcodeOp(entry, 0, opcode, inputs, output);
    }

    private Varnode constant(long value) {
        return new Varnode(currentProgram.getAddressFactory().getConstantSpace().getAddress(value), 8);
    }

    private Varnode register(String name) {
        var register = currentProgram.getRegister(name);
        return new Varnode(register.getAddress(), register.getMinimumByteSize());
    }

    private void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
