package turboheader.il2cpp.analysis.sharedgeneric;

import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.util.task.TaskMonitor;

final class ReferenceGenericCallEvidence {
    private static final int MAX_INSTRUCTIONS = 8192;
    private static final int MAX_TRANSFERS = 65536;
    private static final int MAX_REFERENCES = 65536;
    private static final int MAX_WRITTEN_BYTES = 65536;
    private static final int MAX_VALUES = 128;
    private static final long METHOD_REF_KIND = 6L << 29;
    private final Program program;
    private final Function caller;
    private final TaskMonitor monitor;
    private final Set<Address> writtenBytes = new HashSet<>();
    private Map<Address, Map<Varnode, Value>> states;

    ReferenceGenericCallEvidence(Program program, Function caller, TaskMonitor monitor) {
        this.program = program;
        this.caller = caller;
        this.monitor = monitor;
    }

    boolean matches(Instruction call, Register register, Address slot, int methodSpecIndex) throws Exception {
        monitor.checkCancelled();
        if (states == null) states = solve();
        for (int offset = 0; offset < 8; offset++) {
            if (writtenBytes.contains(slot.addNoWrap(offset))) return false;
        }
        var values = states.get(call.getAddress());
        if (values == null) return false;
        Value result = values.get(new Varnode(register.getAddress(), register.getMinimumByteSize()));
        return result instanceof MetadataSlot metadata && metadata.address() == slot.getOffset() &&
                metadata.token() == (METHOD_REF_KIND | ((long) methodSpecIndex << 1) | 1);
    }

    private Map<Address, Map<Varnode, Value>> solve() throws Exception {
        Map<Address, Instruction> instructions = new LinkedHashMap<>();
        for (var iterator = program.getListing().getInstructions(caller.getBody(), true); iterator.hasNext();) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            if (instructions.size() == MAX_INSTRUCTIONS || instruction.getDelaySlotDepth() != 0) return Map.of();
            instructions.put(instruction.getAddress(), instruction);
        }
        if (!instructions.containsKey(caller.getEntryPoint())) return Map.of();
        Map<Address, Map<Varnode, Value>> incoming = new HashMap<>();
        var work = new ArrayDeque<Address>();
        Set<Address> queued = new HashSet<>();
        merge(caller.getEntryPoint(), Map.of(), incoming, work, queued);
        int references = 0;
        for (Address address : instructions.keySet()) {
            monitor.checkCancelled();
            if (program.getFunctionManager().getFunctionAt(address) != null && !address.equals(caller.getEntryPoint())) {
                merge(address, Map.of(), incoming, work, queued);
            }
            for (var refs = program.getReferenceManager().getReferencesTo(address); refs.hasNext();) {
                monitor.checkCancelled();
                if (++references > MAX_REFERENCES) return Map.of();
                var reference = refs.next();
                if (reference.getReferenceType().isCall() ||
                        (reference.getReferenceType().isFlow() && !instructions.containsKey(reference.getFromAddress()))) {
                    merge(address, Map.of(), incoming, work, queued);
                }
            }
        }
        int transfers = 0;
        while (!work.isEmpty()) {
            monitor.checkCancelled();
            if (++transfers > MAX_TRANSFERS) return Map.of();
            Address address = work.removeFirst();
            queued.remove(address);
            Instruction instruction = instructions.get(address);
            var values = new HashMap<>(incoming.get(address));
            var flow = instruction.getFlowType();
            if (flow.isJump() && flow.isComputed()) return Map.of();
            PcodeOp[] operations = instruction.getPcode();
            if (operations.length > 256) return Map.of();
            if (flow == RefType.FALL_THROUGH && InstructionEffectSummary.hasBranch(operations)) {
                var writes = InstructionEffectSummary.localBranchWrites(operations, instruction.getFallThrough());
                if (writes.isEmpty()) return Map.of();
                for (Varnode output : writes.orElseThrow()) {
                    values.keySet().removeIf(key -> key.isRegister() && key.intersects(output));
                }
            }
            else if (!transfer(operations, values, flow.isJump())) {
                return Map.of();
            }
            values.keySet().removeIf(node -> !node.isRegister());
            if (flow.isJump()) {
                for (Address target : instruction.getFlows()) {
                    if (instructions.containsKey(target)) merge(target, values, incoming, work, queued);
                    else if (caller.getBody().contains(target)) return Map.of();
                }
            }
            Address next = instruction.getFallThrough();
            if (next != null) {
                if (!instructions.containsKey(next)) return Map.of();
                merge(next, values, incoming, work, queued);
            }
        }
        return incoming;
    }

    private boolean transfer(PcodeOp[] operations, Map<Varnode, Value> values, boolean jump) {
        for (PcodeOp op : operations) {
            if (op.getOpcode() == PcodeOp.STORE) {
                if (!recordStore(op, values)) return false;
                values.values().removeIf(value -> value instanceof MetadataSlot);
                continue;
            }
            if (op.getOpcode() == PcodeOp.CALLOTHER || op.getOpcode() == PcodeOp.BRANCHIND) return false;
            if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) {
                preserveCallConstants(values, op);
                continue;
            }
            if (op.getOpcode() == PcodeOp.RETURN) continue;
            if (op.getOpcode() == PcodeOp.BRANCH || op.getOpcode() == PcodeOp.CBRANCH) {
                if (!jump || !op.getInput(0).isAddress()) return false;
                continue;
            }
            Varnode output = op.getOutput();
            if (output == null) continue;
            Value result = evaluate(program, op, values);
            if (output.isRegister()) {
                values.keySet().removeIf(key -> key.isRegister() && key.intersects(output));
            }
            values.remove(output);
            if (result != null) values.put(output, result);
            if (values.size() > MAX_VALUES) return false;
        }
        return true;
    }

    private static void merge(Address address, Map<Varnode, Value> values,
            Map<Address, Map<Varnode, Value>> incoming, ArrayDeque<Address> work, Set<Address> queued) {
        var previous = incoming.get(address);
        boolean changed;
        if (previous == null) {
            incoming.put(address, new HashMap<>(values));
            changed = true;
        }
        else {
            changed = previous.entrySet().removeIf(entry -> !Objects.equals(entry.getValue(), values.get(entry.getKey())));
        }
        if (changed && queued.add(address)) work.addLast(address);
    }

    private void preserveCallConstants(Map<Varnode, Value> values, PcodeOp operation) {
        Function target = operation.getOpcode() == PcodeOp.CALL
                ? program.getFunctionManager().getFunctionAt(operation.getInput(0).getAddress()) : null;
        var convention = target == null || target.hasCustomVariableStorage() ? null : target.getCallingConvention();
        Varnode[] preserved = convention == null ? null : convention.getUnaffectedList();
        values.entrySet().removeIf(entry -> !(entry.getValue() instanceof Constant) ||
                !preserved(entry.getKey(), preserved));
    }

    private static boolean preserved(Varnode node, Varnode[] registers) {
        if (!node.isRegister() || registers == null) return false;
        for (Varnode register : registers) {
            if (register.equals(node)) return true;
        }
        return false;
    }

    private boolean recordStore(PcodeOp operation, Map<Varnode, Value> values) {
        if (!operation.getInput(0).isConstant() || operation.getInput(0).getOffset() !=
                program.getAddressFactory().getDefaultAddressSpace().getSpaceID()) return false;
        if (!(value(operation.getInput(1), values) instanceof Constant destination)) return true;
        int size = operation.getInput(2).getSize();
        if (size > MAX_VALUES) return false;
        try {
            Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(destination.address());
            for (int offset = 0; offset < size; offset++) {
                writtenBytes.add(address.addNoWrap(offset));
                if (writtenBytes.size() > MAX_WRITTEN_BYTES) return false;
            }
        }
        catch (ghidra.program.model.address.AddressOverflowException e) {
            return false;
        }
        return true;
    }

    private static Value evaluate(Program program, PcodeOp op, Map<Varnode, Value> values) {
        try {
            Value first = op.getNumInputs() > 0 ? value(op.getInput(0), values) : null;
            if (op.getOpcode() == PcodeOp.COPY && op.getOutput().getSize() == op.getInput(0).getSize()) {
                return first;
            }
            if ((op.getOpcode() == PcodeOp.INT_ADD || op.getOpcode() == PcodeOp.INT_SUB) &&
                    first instanceof Constant left && value(op.getInput(1), values) instanceof Constant right) {
                long result = op.getOpcode() == PcodeOp.INT_ADD
                        ? Math.addExact(left.address(), right.address()) : Math.subtractExact(left.address(), right.address());
                return result >= 0 && op.getOutput().getSize() == 8 ? new Constant(result) : null;
            }
            if (op.getOpcode() != PcodeOp.LOAD || op.getOutput().getSize() != 8 ||
                    !op.getInput(0).isConstant() ||
                    op.getInput(0).getOffset() != program.getAddressFactory().getDefaultAddressSpace().getSpaceID() ||
                    !(value(op.getInput(1), values) instanceof Constant base)) return null;
            Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(base.address());
            var block = program.getMemory().getBlock(address);
            if (block == null || !block.isInitialized() || !block.isRead() ||
                    !block.contains(address.addNoWrap(7))) return null;
            long contents = program.getMemory().getLong(address);
            if ((block.getName().equals(".got") || block.getName().equals(".got.plt")) &&
                    !block.isWrite() && contents > 0) {
                return new Constant(contents);
            }
            if (contents >>> 29 == 6 && (contents & 1) != 0) {
                // Track the slot identity, not its runtime contents.
                return new MetadataSlot(address.getOffset(), contents);
            }
            return null;
        }
        catch (ArithmeticException | ghidra.program.model.address.AddressOverflowException |
                ghidra.program.model.mem.MemoryAccessException e) {
            return null;
        }
    }

    private static Value value(Varnode node, Map<Varnode, Value> values) {
        return node.isConstant() ? new Constant(node.getOffset()) : values.get(node);
    }

    private sealed interface Value {
    }

    private record Constant(long address) implements Value {
    }

    private record MetadataSlot(long address, long token) implements Value {
    }
}
