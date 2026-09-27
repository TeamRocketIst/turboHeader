package turboheader.il2cpp.analysis.delegatecall;

import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import turboheader.il2cpp.analysis.ssa.SsaIdentityResolver;

public final class Il2CppDelegateCallProofTest {
    private static final long CALLSITE = 0x1040;
    private static final int TYPE_ID = 7;
    private static final String OBJECT_TYPE = "System_Action_int__o*";
    private static final String SIGNATURE =
            "void delegate_invoke (Il2CppMethodPointer methodCode, int32_t value, " +
            "const MethodInfo* method);";

    public static void main(String[] args) {
        acceptsOneExactDelegateObject();
        acceptsCopiesAndUnanimousMerges();
        acceptsOneSharedMergedValue();
        rejectsInexactFieldObjects();
        rejectsSeparateAmbiguousMerges();
        rejectsDifferentDelegateObjects();
        rejectsMissingAndMismatchedTypeEvidence();
        System.out.println("delegate-call proof tests passed");
    }

    private static void acceptsOneExactDelegateObject() {
        Node delegate = root();
        var resolution = resolve(delegate, delegate, delegate,
                types(delegate), signatures(OBJECT_TYPE));
        require(resolution.status() == Il2CppDelegateCallProof.Status.PROVEN,
                "exact delegate call should be proven");
        require(resolution.proof().orElseThrow().equals(
                new Il2CppDelegateCallProof.Proof(
                        CALLSITE, TYPE_ID, OBJECT_TYPE, SIGNATURE)),
                "exact delegate proof");
    }

    private static void acceptsCopiesAndUnanimousMerges() {
        Node delegate = root();
        Node target = merge(copy(delegate), copy(copy(delegate)));
        Node methodCode = copy(delegate);
        Node methodInfo = merge(delegate, copy(delegate));
        require(resolve(target, methodCode, methodInfo,
                types(delegate), signatures(OBJECT_TYPE)).status() ==
                Il2CppDelegateCallProof.Status.PROVEN,
                "copies of one delegate should remain exact");
    }

    private static void acceptsOneSharedMergedValue() {
        Node merged = merge(root(), root());
        require(resolve(merged, merged, merged,
                types(merged), signatures(OBJECT_TYPE)).status() ==
                Il2CppDelegateCallProof.Status.PROVEN,
                "one shared merged value should remain exact at the callsite");
    }

    private static void rejectsInexactFieldObjects() {
        Node delegate = root();
        Node unknown = merge(root(), root());
        require(resolve(unknown, delegate, delegate, types(delegate),
                signatures(OBJECT_TYPE)).status() ==
                Il2CppDelegateCallProof.Status.TARGET_OBJECT_NOT_EXACT,
                "unknown target object");
        require(resolve(delegate, unknown, delegate, types(delegate),
                signatures(OBJECT_TYPE)).status() ==
                Il2CppDelegateCallProof.Status.METHOD_CODE_OBJECT_NOT_EXACT,
                "unknown method-code object");
        require(resolve(delegate, delegate, unknown, types(delegate),
                signatures(OBJECT_TYPE)).status() ==
                Il2CppDelegateCallProof.Status.METHOD_INFO_OBJECT_NOT_EXACT,
                "unknown MethodInfo object");
    }

    private static void rejectsSeparateAmbiguousMerges() {
        Node first = root();
        Node second = root();
        Node target = merge(first, second);
        Node methodCode = merge(first, second);
        Node methodInfo = merge(first, second);
        require(resolve(target, methodCode, methodInfo, types(target),
                signatures(OBJECT_TYPE)).status() ==
                Il2CppDelegateCallProof.Status.TARGET_OBJECT_NOT_EXACT,
                "separate ambiguous merges must not be treated as one object");
    }

    private static void rejectsDifferentDelegateObjects() {
        Node first = root();
        Node second = root();
        require(resolve(first, second, first, types(first),
                signatures(OBJECT_TYPE)).status() ==
                Il2CppDelegateCallProof.Status.DELEGATE_OBJECT_MISMATCH,
                "fields from distinct delegates must not be combined");
    }

    private static void rejectsMissingAndMismatchedTypeEvidence() {
        Node delegate = root();
        require(resolve(delegate, delegate, delegate, ignored -> Optional.empty(),
                signatures(OBJECT_TYPE)).status() ==
                Il2CppDelegateCallProof.Status.TYPE_NOT_EXACT,
                "missing static type");
        require(resolve(delegate, delegate, delegate, types(delegate),
                ignored -> Optional.empty()).status() ==
                Il2CppDelegateCallProof.Status.NO_CATALOG_ENTRY,
                "missing catalogue entry");
        require(resolve(delegate, delegate, delegate, types(delegate),
                signatures("System_Action_long__o*")).status() ==
                Il2CppDelegateCallProof.Status.CATALOG_TYPE_MISMATCH,
                "catalogue object type mismatch");
        require(resolve(delegate, delegate, delegate, types(delegate),
                ignored -> Optional.of(new Il2CppDelegateCallProof.SignatureEntry(
                        TYPE_ID + 1, OBJECT_TYPE, SIGNATURE))).status() ==
                Il2CppDelegateCallProof.Status.CATALOG_TYPE_MISMATCH,
                "catalogue TypeId mismatch");
    }

    private static Il2CppDelegateCallProof.Resolution resolve(Node target,
            Node methodCode, Node methodInfo,
            Il2CppDelegateCallProof.TypeLookup<Node> types,
            Il2CppDelegateCallProof.SignatureLookup signatures) {
        var callsite = new Il2CppDelegateCallProof.Callsite<>(
                CALLSITE, target, methodCode, methodInfo);
        return Il2CppDelegateCallProof.resolve(callsite, Node::value, types, signatures);
    }

    private static Il2CppDelegateCallProof.TypeLookup<Node> types(Node delegate) {
        Map<Node, Il2CppDelegateCallProof.TypeIdentity> types = new IdentityHashMap<>();
        types.put(delegate, new Il2CppDelegateCallProof.TypeIdentity(TYPE_ID, OBJECT_TYPE));
        return value -> Optional.ofNullable(types.get(value));
    }

    private static Il2CppDelegateCallProof.SignatureLookup signatures(String objectType) {
        return typeId -> typeId == TYPE_ID
                ? Optional.of(new Il2CppDelegateCallProof.SignatureEntry(
                        TYPE_ID, objectType, SIGNATURE))
                : Optional.empty();
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

    private record Node(SsaIdentityResolver.Operation operation, List<Node> inputs) {
        private Node(SsaIdentityResolver.Operation operation, Node... inputs) {
            this(operation, List.of(inputs));
        }

        private SsaIdentityResolver.Value<Node> value() {
            return new SsaIdentityResolver.Value<>(operation, inputs);
        }
    }
}
