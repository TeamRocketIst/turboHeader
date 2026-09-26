package turboheader.il2cpp.analysis;

public final class TypeInfoSourcePolicyTest {
    public static void main(String[] args) {
        acceptsOneReadOnlyPointerReference();
        rejectsMutableAndExecutableSources();
        rejectsMalformedAndAmbiguousSources();
        System.out.println("TypeInfo source policy tests passed");
    }

    private static void acceptsOneReadOnlyPointerReference() {
        require(TypeInfoSourcePolicy.accepts(8, evidence(
                8, true, true, false, false, 1, true, true, true)),
                "read-only pointer source");
    }

    private static void rejectsMutableAndExecutableSources() {
        require(!TypeInfoSourcePolicy.accepts(8, evidence(
                8, true, true, true, false, 1, true, true, true)),
                "writable source must be rejected");
        require(!TypeInfoSourcePolicy.accepts(8, evidence(
                8, true, true, false, true, 1, true, true, true)),
                "executable source must be rejected");
        require(!TypeInfoSourcePolicy.accepts(8, evidence(
                8, true, false, false, false, 1, true, true, true)),
                "unreadable source must be rejected");
    }

    private static void rejectsMalformedAndAmbiguousSources() {
        require(!TypeInfoSourcePolicy.accepts(8, evidence(
                4, true, true, false, false, 1, true, true, true)),
                "short pointer must be rejected");
        require(!TypeInfoSourcePolicy.accepts(8, evidence(
                8, false, true, false, false, 1, true, true, true)),
                "non-pointer data must be rejected");
        require(!TypeInfoSourcePolicy.accepts(8, evidence(
                8, true, true, false, false, 2, true, true, true)),
                "multiple references must be rejected");
        require(!TypeInfoSourcePolicy.accepts(8, evidence(
                8, true, true, false, false, 1, false, true, true)),
                "non-data reference must be rejected");
        require(!TypeInfoSourcePolicy.accepts(8, evidence(
                8, true, true, false, false, 1, true, false, true)),
                "non-primary reference must be rejected");
        require(!TypeInfoSourcePolicy.accepts(8, evidence(
                8, true, true, false, false, 1, true, true, false)),
                "mismatched pointer must be rejected");
    }

    private static TypeInfoSourcePolicy.Evidence evidence(int dataLength,
            boolean pointerData, boolean readable, boolean writable,
            boolean executable, int referenceCount, boolean dataReference,
            boolean primaryReference, boolean valueMatchesReference) {
        return new TypeInfoSourcePolicy.Evidence(dataLength, pointerData, readable,
                writable, executable, referenceCount, dataReference,
                primaryReference, valueMatchesReference);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
