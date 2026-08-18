package turboheader.il2cpp;

public final class Il2CppHelperProofPolicyTest {
    public static void main(String[] args) {
        check(Il2CppHelperProofPolicy.provesDirectTailForwarder(2, 1, true, true),
                "two-instruction terminal forwarder rejected");
        check(!Il2CppHelperProofPolicy.provesDirectTailForwarder(0, 1, true, true),
                "empty body accepted");
        check(!Il2CppHelperProofPolicy.provesDirectTailForwarder(5, 1, true, true),
                "oversized body accepted");
        check(!Il2CppHelperProofPolicy.provesDirectTailForwarder(2, 2, true, true),
                "multiple transfers accepted");
        check(!Il2CppHelperProofPolicy.provesDirectTailForwarder(2, 1, false, true),
                "wrong target accepted");
        check(!Il2CppHelperProofPolicy.provesDirectTailForwarder(2, 1, true, false),
                "non-terminal call accepted");
        System.out.println("IL2CPP helper-proof policy tests passed");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
