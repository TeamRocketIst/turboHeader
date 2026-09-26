package turboheader.il2cpp.analysis.interfacecall;

import java.util.List;

public final class ExactSsaValueResolverTest {
    public static void main(String[] args) {
        resolvesSeededLoopToFixedPoint();
        rejectsConflictingLoopSeeds();
        rejectsUnknownLoopInputs();
        rejectsUnseededCyclesAndExcessiveGraphs();
        System.out.println("exact SSA value resolver tests passed");
    }

    private static void resolvesSeededLoopToFixedPoint() {
        Node forward = merge();
        Node backedge = copy(forward);
        forward.inputs = List.of(type(7), backedge);
        assertOrigin(allocation(forward), ExactSsaValueResolver.Kind.EXACT_ALLOCATION, 7,
                "seeded loop allocation");

        Node reverse = merge();
        Node reverseBackedge = copy(reverse);
        reverse.inputs = List.of(reverseBackedge, type(7));
        assertOrigin(allocation(reverse), ExactSsaValueResolver.Kind.EXACT_ALLOCATION, 7,
                "predecessor order");
    }

    private static void rejectsConflictingLoopSeeds() {
        Node loop = merge();
        Node backedge = merge(copy(loop), type(8));
        loop.inputs = List.of(type(7), backedge);
        assertOrigin(loop, ExactSsaValueResolver.Kind.CONFLICT, 0,
                "conflicting loop seeds");
    }

    private static void rejectsUnknownLoopInputs() {
        Node loop = merge();
        Node backedge = merge(copy(loop), unknown());
        loop.inputs = List.of(type(7), backedge);
        assertOrigin(loop, ExactSsaValueResolver.Kind.UNKNOWN, 0,
                "unknown loop input");
    }

    private static void rejectsUnseededCyclesAndExcessiveGraphs() {
        Node cycle = copy(null);
        cycle.inputs = List.of(cycle);
        assertOrigin(cycle, ExactSsaValueResolver.Kind.UNKNOWN, 0,
                "unseeded cycle");

        Node chain = type(7);
        for (int index = 0; index < 140; index++) {
            chain = copy(chain);
        }
        assertOrigin(chain, ExactSsaValueResolver.Kind.UNKNOWN, 0,
                "oversized graph");
    }

    private static void assertOrigin(Node node, ExactSsaValueResolver.Kind kind,
            long value, String message) {
        var origin = new ExactSsaValueResolver<Node>(Node::value).resolve(node);
        if (origin.kind() != kind || origin.value() != value) {
            throw new AssertionError(message + ": " + origin);
        }
    }

    private static Node unknown() {
        return new Node(ExactSsaValueResolver.Operation.UNKNOWN, 0);
    }

    private static Node type(int value) {
        return new Node(ExactSsaValueResolver.Operation.EXACT_TYPE, value);
    }

    private static Node allocation(Node type) {
        return new Node(ExactSsaValueResolver.Operation.ALLOCATION, 0, type);
    }

    private static Node copy(Node input) {
        return input == null
                ? new Node(ExactSsaValueResolver.Operation.COPY, 0)
                : new Node(ExactSsaValueResolver.Operation.COPY, 0, input);
    }

    private static Node merge(Node... inputs) {
        return new Node(ExactSsaValueResolver.Operation.MERGE, 0, inputs);
    }

    private static final class Node {
        private final ExactSsaValueResolver.Operation operation;
        private final long literal;
        private List<Node> inputs;

        private Node(ExactSsaValueResolver.Operation operation, long literal,
                Node... inputs) {
            this.operation = operation;
            this.literal = literal;
            this.inputs = List.of(inputs);
        }

        private ExactSsaValueResolver.Value<Node> value() {
            return new ExactSsaValueResolver.Value<>(operation, literal, inputs);
        }
    }
}
