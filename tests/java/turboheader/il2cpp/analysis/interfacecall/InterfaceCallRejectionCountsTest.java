package turboheader.il2cpp.analysis.interfacecall;

import java.util.List;

public final class InterfaceCallRejectionCountsTest {
    public static void main(String[] args) {
        var counts = InterfaceCallRejectionCounts.count(List.of(
                InterfaceCallRejectionCounts.Reason.RECEIVER,
                InterfaceCallRejectionCounts.Reason.RECEIVER,
                InterfaceCallRejectionCounts.Reason.SLOT,
                InterfaceCallRejectionCounts.Reason.CATALOG));

        require(counts.total() == 4, "rejection total");
        require(counts.receiver() == 2 && counts.slot() == 1 && counts.catalog() == 1,
                "rejection categories");
        require(counts.summary().equals("receiver:2,slot:1,catalog:1"),
                "rejection summary");
        require(InterfaceCallRejectionCounts.none().summary().equals("none"),
                "empty rejection summary");

        boolean rejected = false;
        try {
            InterfaceCallRejectionCounts.reason(Il2CppInterfaceCallProof.Status.PROVEN);
        }
        catch (IllegalArgumentException expected) {
            rejected = true;
        }
        require(rejected, "proven status was counted as a rejection");
        require(InterfaceCallRejectionCounts.reason(
                Il2CppInterfaceCallProof.Status.INTERFACE_NOT_EXACT_TYPE) ==
                InterfaceCallRejectionCounts.Reason.INTERFACE_TYPE,
                "interface rejection mapping");
        System.out.println("interface-call rejection count tests passed");
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
