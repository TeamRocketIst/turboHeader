package turboheader.il2cpp.metadata;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public final class Il2CppDelegateSignatureCatalogTest {
    private static final String OBJECT_TYPE = "System_Action_int__o*";
    private static final String SIGNATURE =
            "void delegate_invoke (Il2CppMethodPointer methodCode, int32_t value, " +
            "const MethodInfo* method);";

    public static void main(String[] args) throws Exception {
        var first = new ScriptMethodReader.ScriptDelegateSignature(
                7, OBJECT_TYPE, SIGNATURE);
        var alias = new ScriptMethodReader.ScriptDelegateSignature(
                9, OBJECT_TYPE, SIGNATURE);
        var catalog = Il2CppDelegateSignatureCatalog.fromScript(
                data(List.of(alias, first, first))).orElseThrow();
        check(catalog.entries().size() == 2, "equal row deduplication");
        check(catalog.entries().get(0).typeId() == 7, "deterministic TypeId order");
        check(catalog.forTypeId(9).orElseThrow().signature().equals(SIGNATURE),
                "TypeId lookup");
        check(catalog.forObjectType(OBJECT_TYPE).orElseThrow().equals(SIGNATURE),
                "object type lookup");

        byte[] encoded = Il2CppDelegateSignatureCodec.encode(catalog);
        var decoded = Il2CppDelegateSignatureCodec.decode(encoded);
        check(decoded.entries().equals(catalog.entries()), "codec round trip");

        var absent = new ScriptMethodReader.ScriptData(
                List.of(), List.of(), List.of(), List.of());
        check(Il2CppDelegateSignatureCatalog.fromScript(absent).isEmpty(),
                "absent table remains disabled");

        expectFailure(List.of(first, new ScriptMethodReader.ScriptDelegateSignature(
                7, "System_Action_long__o*", SIGNATURE)), "conflicting TypeId");
        expectFailure(List.of(first, new ScriptMethodReader.ScriptDelegateSignature(
                9, OBJECT_TYPE, "int32_t delegate_invoke (Il2CppMethodPointer methodCode);")),
                "conflicting object type");

        byte[] trailing = Arrays.copyOf(encoded, encoded.length + 1);
        try {
            Il2CppDelegateSignatureCodec.decode(trailing);
            throw new AssertionError("trailing stored data");
        }
        catch (IOException expected) {
            // Expected.
        }

        byte[] truncated = Arrays.copyOf(encoded, encoded.length - 1);
        try {
            Il2CppDelegateSignatureCodec.decode(truncated);
            throw new AssertionError("truncated stored data");
        }
        catch (IOException expected) {
            // Expected.
        }

        System.out.println("delegate signature catalogue tests passed");
    }

    private static ScriptMethodReader.ScriptData data(
            List<ScriptMethodReader.ScriptDelegateSignature> entries) {
        return new ScriptMethodReader.ScriptData(List.of(), List.of(), List.of(), List.of(),
                Optional.empty(), Optional.of(entries));
    }

    private static void expectFailure(
            List<ScriptMethodReader.ScriptDelegateSignature> entries, String label)
            throws Exception {
        try {
            Il2CppDelegateSignatureCatalog.fromScript(data(entries));
            throw new AssertionError(label);
        }
        catch (IOException expected) {
            // Expected.
        }
    }

    private static void check(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }
}
