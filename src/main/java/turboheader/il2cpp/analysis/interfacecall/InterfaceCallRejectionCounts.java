package turboheader.il2cpp.analysis.interfacecall;

import java.util.ArrayList;
import java.util.List;

public record InterfaceCallRejectionCounts(int receiver, int interfaceType,
        int slot, int slotRange, int catalog, int target) {
    public InterfaceCallRejectionCounts {
        if (receiver < 0 || interfaceType < 0 || slot < 0 || slotRange < 0 ||
                catalog < 0 || target < 0) {
            throw new IllegalArgumentException("interface-call rejection count is negative");
        }
    }

    static InterfaceCallRejectionCounts count(Iterable<Reason> reasons) {
        int receiver = 0;
        int interfaceType = 0;
        int slot = 0;
        int slotRange = 0;
        int catalog = 0;
        int target = 0;
        for (var reason : reasons) {
            switch (reason) {
                case RECEIVER -> receiver++;
                case INTERFACE_TYPE -> interfaceType++;
                case SLOT -> slot++;
                case SLOT_RANGE -> slotRange++;
                case CATALOG -> catalog++;
                case TARGET -> target++;
            }
        }
        return new InterfaceCallRejectionCounts(receiver, interfaceType, slot,
                slotRange, catalog, target);
    }

    static InterfaceCallRejectionCounts none() {
        return new InterfaceCallRejectionCounts(0, 0, 0, 0, 0, 0);
    }

    static Reason reason(Il2CppInterfaceCallProof.Status status) {
        return switch (status) {
            case RECEIVER_NOT_EXACT_ALLOCATION -> Reason.RECEIVER;
            case INTERFACE_NOT_EXACT_TYPE -> Reason.INTERFACE_TYPE;
            case SLOT_NOT_CONSTANT -> Reason.SLOT;
            case SLOT_OUT_OF_RANGE -> Reason.SLOT_RANGE;
            case NO_CATALOG_ENTRY -> Reason.CATALOG;
            case INVALID_TARGET -> Reason.TARGET;
            case PROVEN -> throw new IllegalArgumentException(
                    "proven call is not a rejection");
        };
    }

    public int total() {
        return receiver + interfaceType + slot + slotRange + catalog + target;
    }

    public String summary() {
        List<String> parts = new ArrayList<>();
        add(parts, "receiver", receiver);
        add(parts, "interface", interfaceType);
        add(parts, "slot", slot);
        add(parts, "slot-range", slotRange);
        add(parts, "catalog", catalog);
        add(parts, "target", target);
        return parts.isEmpty() ? "none" : String.join(",", parts);
    }

    private static void add(List<String> parts, String label, int count) {
        if (count != 0) {
            parts.add(label + ":" + count);
        }
    }

    public enum Reason {
        RECEIVER("receiver"),
        INTERFACE_TYPE("interface"),
        SLOT("slot"),
        SLOT_RANGE("slot-range"),
        CATALOG("catalog"),
        TARGET("target");

        private final String label;

        Reason(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }
}
