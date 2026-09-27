package turboheader.il2cpp.analysis.delegatecall;

import java.util.List;

public final class DelegateCallRejectionCountsTest {
    public static void main(String[] args) {
        var counts = DelegateCallRejectionCounts.count(List.of(
                DelegateCallRejectionCounts.Reason.TARGET_OBJECT,
                DelegateCallRejectionCounts.Reason.OBJECT_MISMATCH,
                DelegateCallRejectionCounts.Reason.OBJECT_MISMATCH,
                DelegateCallRejectionCounts.Reason.CATALOG,
                DelegateCallRejectionCounts.Reason.CALLSITE));

        require(counts.total() == 5, "rejection total");
        require(counts.targetObject() == 1 && counts.objectMismatch() == 2 &&
                counts.catalog() == 1 && counts.callsite() == 1,
                "rejection categories");
        require(counts.summary().equals(
                "target-object:1,object-mismatch:2,catalog:1,callsite:1"),
                "rejection summary");
        require(DelegateCallRejectionCounts.none().summary().equals("none"),
                "empty rejection summary");
        require(DelegateCallRejectionCounts.reason(
                Il2CppDelegateCallProof.Status.CATALOG_TYPE_MISMATCH) ==
                DelegateCallRejectionCounts.Reason.CATALOG_TYPE,
                "catalogue type mapping");

        boolean rejected = false;
        try {
            DelegateCallRejectionCounts.reason(Il2CppDelegateCallProof.Status.PROVEN);
        }
        catch (IllegalArgumentException expected) {
            rejected = true;
        }
        require(rejected, "proven status was counted as a rejection");
        System.out.println("delegate-call rejection count tests passed");
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
