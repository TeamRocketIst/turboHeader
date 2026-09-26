package turboheader.il2cpp.analysis;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;

public final class Il2CppInterfaceCallProofTest {
    private static final long CALLSITE = 0x1040;
    private static final long TARGET = 0x2080;

    public static void main(String[] args) {
        acceptsExactOrigins();
        acceptsCopiesAndEqualMerges();
        acceptsLoopCarriedTypeInfo();
        rejectsUnknownAndConflictingReceivers();
        rejectsInexactInterfaceAndSlotValues();
        rejectsMissingAndInvalidTargets();
        rejectsCyclesAndExcessiveGraphs();
        System.out.println("interface-call proof tests passed");
    }

    private static void acceptsExactOrigins() {
        Node receiver = allocation(type(7));
        Node interfaceType = type(3);
        Node slot = constant(1);
        var result = resolve(receiver, interfaceType, slot, lookup(7, 3, 1, TARGET));
        require(result.status() == Il2CppInterfaceCallProof.Status.PROVEN,
                "exact dispatch should be proven");
        require(result.proof().orElseThrow().equals(
                new Il2CppInterfaceCallProof.Proof(CALLSITE, TARGET, 7, 3, 1)),
                "exact dispatch proof");
    }

    private static void acceptsCopiesAndEqualMerges() {
        Node receiver = merge(copy(allocation(type(7))), allocation(type(7)));
        Node interfaceType = merge(type(3), copy(type(3)));
        Node slot = copy(constant(1));
        require(resolve(receiver, interfaceType, slot, lookup(7, 3, 1, TARGET))
                .status() == Il2CppInterfaceCallProof.Status.PROVEN,
                "equal SSA origins should remain exact");
    }

    private static void acceptsLoopCarriedTypeInfo() {
        Node loopType = merge();
        Node backedge = copy(loopType);
        loopType.inputs = List.of(type(7), backedge);
        Node receiver = allocation(loopType);
        require(resolve(receiver, type(3), constant(1), lookup(7, 3, 1, TARGET))
                .status() == Il2CppInterfaceCallProof.Status.PROVEN,
                "loop-carried TypeInfo should reach a fixed point");
    }

    private static void rejectsUnknownAndConflictingReceivers() {
        require(resolve(unknown(), type(3), constant(1), lookup(7, 3, 1, TARGET))
                .status() == Il2CppInterfaceCallProof.Status.RECEIVER_NOT_EXACT_ALLOCATION,
                "factory receiver must be rejected");
        Node conflict = merge(allocation(type(7)), allocation(type(8)));
        require(resolve(conflict, type(3), constant(1), lookup(7, 3, 1, TARGET))
                .status() == Il2CppInterfaceCallProof.Status.RECEIVER_NOT_EXACT_ALLOCATION,
                "polymorphic receiver must be rejected");
        require(resolve(type(7), type(3), constant(1), lookup(7, 3, 1, TARGET))
                .status() == Il2CppInterfaceCallProof.Status.RECEIVER_NOT_EXACT_ALLOCATION,
                "static receiver type alone must be rejected");
    }

    private static void rejectsInexactInterfaceAndSlotValues() {
        Node receiver = allocation(type(7));
        require(resolve(receiver, unknown(), constant(1), lookup(7, 3, 1, TARGET))
                .status() == Il2CppInterfaceCallProof.Status.INTERFACE_NOT_EXACT_TYPE,
                "unknown interface must be rejected");
        require(resolve(receiver, type(3), unknown(), lookup(7, 3, 1, TARGET))
                .status() == Il2CppInterfaceCallProof.Status.SLOT_NOT_CONSTANT,
                "dynamic slot must be rejected");
        require(resolve(receiver, type(3), constant(-1), lookup(7, 3, 1, TARGET))
                .status() == Il2CppInterfaceCallProof.Status.SLOT_OUT_OF_RANGE,
                "negative slot must be rejected");
    }

    private static void rejectsMissingAndInvalidTargets() {
        Node receiver = allocation(type(7));
        require(resolve(receiver, type(3), constant(1), (a, b, c) -> OptionalLong.empty())
                .status() == Il2CppInterfaceCallProof.Status.NO_CATALOG_ENTRY,
                "missing catalogue tuple must be rejected");
        require(resolve(receiver, type(3), constant(1), (a, b, c) -> OptionalLong.of(0))
                .status() == Il2CppInterfaceCallProof.Status.INVALID_TARGET,
                "zero target must be rejected");
    }

    private static void rejectsCyclesAndExcessiveGraphs() {
        Node cycle = new Node(ExactSsaValueResolver.Operation.COPY, 0);
        cycle.inputs = List.of(cycle);
        require(resolve(cycle, type(3), constant(1), lookup(7, 3, 1, TARGET))
                .status() == Il2CppInterfaceCallProof.Status.RECEIVER_NOT_EXACT_ALLOCATION,
                "cyclic SSA graph must be rejected");

        Node chain = allocation(type(7));
        for (int index = 0; index < 140; index++) {
            chain = copy(chain);
        }
        require(resolve(chain, type(3), constant(1), lookup(7, 3, 1, TARGET))
                .status() == Il2CppInterfaceCallProof.Status.RECEIVER_NOT_EXACT_ALLOCATION,
                "oversized SSA graph must be rejected");
    }

    private static Il2CppInterfaceCallProof.Resolution resolve(Node receiver,
            Node interfaceType, Node slot, Il2CppInterfaceCallProof.DispatchLookup lookup) {
        var callsite = new Il2CppInterfaceCallProof.Callsite<>(
                CALLSITE, receiver, interfaceType, slot);
        return Il2CppInterfaceCallProof.resolve(callsite, Node::value, lookup);
    }

    private static Il2CppInterfaceCallProof.DispatchLookup lookup(
            int receiver, int interfaceType, int slot, long target) {
        Map<Key, Long> entries = new HashMap<>();
        entries.put(new Key(receiver, interfaceType, slot), target);
        return (actualReceiver, actualInterface, actualSlot) -> {
            Long result = entries.get(new Key(actualReceiver, actualInterface, actualSlot));
            return result == null ? OptionalLong.empty() : OptionalLong.of(result);
        };
    }

    private static Node unknown() {
        return new Node(ExactSsaValueResolver.Operation.UNKNOWN, 0);
    }

    private static Node type(int value) {
        return new Node(ExactSsaValueResolver.Operation.EXACT_TYPE, value);
    }

    private static Node constant(long value) {
        return new Node(ExactSsaValueResolver.Operation.EXACT_CONSTANT, value);
    }

    private static Node allocation(Node type) {
        return new Node(ExactSsaValueResolver.Operation.ALLOCATION, 0, type);
    }

    private static Node copy(Node input) {
        return new Node(ExactSsaValueResolver.Operation.COPY, 0, input);
    }

    private static Node merge(Node... inputs) {
        return new Node(ExactSsaValueResolver.Operation.MERGE, 0, inputs);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static final class Node {
        private final ExactSsaValueResolver.Operation operation;
        private final long literal;
        private List<Node> inputs;

        Node(ExactSsaValueResolver.Operation operation, long literal, Node... inputs) {
            this.operation = operation;
            this.literal = literal;
            this.inputs = List.of(inputs);
        }

        ExactSsaValueResolver.Value<Node> value() {
            return new ExactSsaValueResolver.Value<>(operation, literal, inputs);
        }
    }

    private record Key(int receiver, int interfaceType, int slot) {
    }
}
