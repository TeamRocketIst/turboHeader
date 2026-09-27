package turboheader.il2cpp.analysis.delegatecall;

import java.util.ArrayList;
import java.util.List;

public record DelegateCallRejectionCounts(int targetObject, int methodCodeObject,
        int methodInfoObject, int objectMismatch, int type, int catalog,
        int catalogType, int callsite) {
    public DelegateCallRejectionCounts {
        if (targetObject < 0 || methodCodeObject < 0 || methodInfoObject < 0 ||
                objectMismatch < 0 || type < 0 || catalog < 0 || catalogType < 0 ||
                callsite < 0) {
            throw new IllegalArgumentException("delegate-call rejection count is negative");
        }
    }

    static DelegateCallRejectionCounts count(Iterable<Reason> reasons) {
        int targetObject = 0;
        int methodCodeObject = 0;
        int methodInfoObject = 0;
        int objectMismatch = 0;
        int type = 0;
        int catalog = 0;
        int catalogType = 0;
        int callsite = 0;
        for (Reason reason : reasons) {
            switch (reason) {
                case TARGET_OBJECT -> targetObject++;
                case METHOD_CODE_OBJECT -> methodCodeObject++;
                case METHOD_INFO_OBJECT -> methodInfoObject++;
                case OBJECT_MISMATCH -> objectMismatch++;
                case TYPE -> type++;
                case CATALOG -> catalog++;
                case CATALOG_TYPE -> catalogType++;
                case CALLSITE -> callsite++;
            }
        }
        return new DelegateCallRejectionCounts(targetObject, methodCodeObject,
                methodInfoObject, objectMismatch, type, catalog, catalogType, callsite);
    }

    static DelegateCallRejectionCounts none() {
        return new DelegateCallRejectionCounts(0, 0, 0, 0, 0, 0, 0, 0);
    }

    static Reason reason(Il2CppDelegateCallProof.Status status) {
        return switch (status) {
            case TARGET_OBJECT_NOT_EXACT -> Reason.TARGET_OBJECT;
            case METHOD_CODE_OBJECT_NOT_EXACT -> Reason.METHOD_CODE_OBJECT;
            case METHOD_INFO_OBJECT_NOT_EXACT -> Reason.METHOD_INFO_OBJECT;
            case DELEGATE_OBJECT_MISMATCH -> Reason.OBJECT_MISMATCH;
            case TYPE_NOT_EXACT -> Reason.TYPE;
            case NO_CATALOG_ENTRY -> Reason.CATALOG;
            case CATALOG_TYPE_MISMATCH -> Reason.CATALOG_TYPE;
            case PROVEN -> throw new IllegalArgumentException(
                    "proven call is not a rejection");
        };
    }

    public int total() {
        return targetObject + methodCodeObject + methodInfoObject + objectMismatch +
                type + catalog + catalogType + callsite;
    }

    public String summary() {
        List<String> parts = new ArrayList<>();
        add(parts, "target-object", targetObject);
        add(parts, "method-code-object", methodCodeObject);
        add(parts, "method-info-object", methodInfoObject);
        add(parts, "object-mismatch", objectMismatch);
        add(parts, "type", type);
        add(parts, "catalog", catalog);
        add(parts, "catalog-type", catalogType);
        add(parts, "callsite", callsite);
        return parts.isEmpty() ? "none" : String.join(",", parts);
    }

    private static void add(List<String> parts, String label, int count) {
        if (count != 0) {
            parts.add(label + ":" + count);
        }
    }

    public enum Reason {
        TARGET_OBJECT,
        METHOD_CODE_OBJECT,
        METHOD_INFO_OBJECT,
        OBJECT_MISMATCH,
        TYPE,
        CATALOG,
        CATALOG_TYPE,
        CALLSITE
    }
}
