package turboheader.il2cpp.analysis;

import java.util.List;

public final class SsaIdentityResolverTest {
    public static void main(String[] args) {
        acceptsIdentityCopiesAndCasts();
        acceptsOnlyUnanimousMerges();
        rejectsCyclesAndExcessiveGraphs();
        rejectsDistinctSameKindRoots();
        System.out.println("SSA identity resolver tests passed");
    }

    private static void acceptsIdentityCopiesAndCasts() {
        Node root = root();
        Node first = copy(root);
        Node second = copy(copy(root));
        var resolver = resolver();
        require(resolver.resolve(root).orElseThrow() == root, "root identity");
        require(resolver.resolve(first).orElseThrow() == root, "copied root identity");
        require(resolver.resolve(second).orElseThrow() == root, "sibling root identity");
    }

    private static void acceptsOnlyUnanimousMerges() {
        Node root = root();
        Node same = merge(copy(root), copy(copy(root)));
        require(resolver().resolve(same).orElseThrow() == root,
                "unanimous merge identity");

        Node mixed = merge(copy(root), copy(root()));
        require(resolver().resolve(mixed).isEmpty(), "mixed merge must be unknown");
        require(resolver().resolve(merge()).isEmpty(), "empty merge must be unknown");
    }

    private static void rejectsCyclesAndExcessiveGraphs() {
        Node cycle = new Node(SsaIdentityResolver.Operation.COPY);
        cycle.inputs = List.of(cycle);
        require(resolver().resolve(cycle).isEmpty(), "cycle must be unknown");

        Node chain = root();
        for (int index = 0; index < 140; index++) {
            chain = copy(chain);
        }
        require(resolver().resolve(chain).isEmpty(), "oversized graph must be unknown");
    }

    private static void rejectsDistinctSameKindRoots() {
        Node firstAllocation = root();
        Node secondAllocation = root();
        require(resolver().resolve(firstAllocation).orElseThrow() !=
                resolver().resolve(secondAllocation).orElseThrow(),
                "distinct allocations must keep distinct identities");
    }

    private static SsaIdentityResolver<Node> resolver() {
        return new SsaIdentityResolver<>(Node::value);
    }

    private static Node root() {
        return new Node(SsaIdentityResolver.Operation.ROOT);
    }

    private static Node copy(Node input) {
        return new Node(SsaIdentityResolver.Operation.COPY, input);
    }

    private static Node merge(Node... inputs) {
        return new Node(SsaIdentityResolver.Operation.MERGE, inputs);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static final class Node {
        private final SsaIdentityResolver.Operation operation;
        private List<Node> inputs;

        private Node(SsaIdentityResolver.Operation operation, Node... inputs) {
            this.operation = operation;
            this.inputs = List.of(inputs);
        }

        private SsaIdentityResolver.Value<Node> value() {
            return new SsaIdentityResolver.Value<>(operation, inputs);
        }
    }
}
