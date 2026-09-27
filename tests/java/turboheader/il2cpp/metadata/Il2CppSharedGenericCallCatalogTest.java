package turboheader.il2cpp.metadata;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public final class Il2CppSharedGenericCallCatalogTest {
    private static final String SIGNATURE =
            "void shared_generic_call (Fixture_List_o* __this, int32_t index, " +
            "Fixture_Item_o** __result, const MethodInfo* method);";

    public static void main(String[] args) throws Exception {
        var first = new ScriptMethodReader.ScriptSharedGenericCall(
                0x100, 0x200, SIGNATURE);
        var second = new ScriptMethodReader.ScriptSharedGenericCall(
                0x120, 0x200, SIGNATURE);
        var catalog = Il2CppSharedGenericCallCatalog.fromScript(
                data(List.of(second, first, first))).orElseThrow();
        check(catalog.entries().size() == 2, "equal row deduplication");
        check(catalog.entries().get(0).methodInfoAddress() == 0x100,
                "deterministic MethodInfo order");
        check(catalog.forMethodInfoAddress(0x120).orElseThrow()
                .signature().equals(SIGNATURE), "MethodInfo lookup");
        check(catalog.forMethodAddress(0x200).size() == 2,
                "shared body lookup");

        byte[] encoded = Il2CppSharedGenericCallCodec.encode(catalog);
        var decoded = Il2CppSharedGenericCallCodec.decode(encoded);
        check(decoded.entries().equals(catalog.entries()), "codec round trip");

        var absent = new ScriptMethodReader.ScriptData(
                List.of(), List.of(), List.of(), List.of());
        check(Il2CppSharedGenericCallCatalog.fromScript(absent).isEmpty(),
                "absent table remains disabled");

        expectFailure(List.of(first, new ScriptMethodReader.ScriptSharedGenericCall(
                0x100, 0x220, SIGNATURE)), "conflicting MethodInfo address");
        expectFailure(List.of(new ScriptMethodReader.ScriptSharedGenericCall(
                0x100, 0x200,
                "void wrong_name (Fixture_Item_o** __result, const MethodInfo* method);")),
                "wrong physical function name");
        String valueSignature = "void shared_generic_call (" +
                "Fixture_Item_o* __result, const MethodInfo* method);";
        var valueCatalog = Il2CppSharedGenericCallCatalog.fromScript(data(List.of(
                new ScriptMethodReader.ScriptSharedGenericCall(
                        0x140, 0x240, valueSignature)))).orElseThrow();
        var valuePrototype = SharedGenericCallSignature.parse(
                valueCatalog.entries().getFirst().signature());
        check(valuePrototype.hasValueResult(), "value result classification");
        check(valuePrototype.resultPointeeType().equals("Fixture_Item_o"),
                "value result pointee");

        expectFailure(List.of(new ScriptMethodReader.ScriptSharedGenericCall(
                0x100, 0x200,
                "void shared_generic_call (Fixture_Item_o __result, " +
                "const MethodInfo* method);")), "result is not a pointer");
        expectFailure(List.of(new ScriptMethodReader.ScriptSharedGenericCall(
                0x100, 0x200,
                "void shared_generic_call (void* __result, " +
                "const MethodInfo* method);")), "void result buffer");

        byte[] trailing = Arrays.copyOf(encoded, encoded.length + 1);
        expectDecodeFailure(trailing, "trailing stored data");
        byte[] truncated = Arrays.copyOf(encoded, encoded.length - 1);
        expectDecodeFailure(truncated, "truncated stored data");

        System.out.println("shared generic call catalogue tests passed");
    }

    private static ScriptMethodReader.ScriptData data(
            List<ScriptMethodReader.ScriptSharedGenericCall> entries) {
        return new ScriptMethodReader.ScriptData(List.of(), List.of(), List.of(), List.of(),
                Optional.empty(), Optional.empty(), Optional.of(entries));
    }

    private static void expectFailure(
            List<ScriptMethodReader.ScriptSharedGenericCall> entries, String label)
            throws Exception {
        try {
            Il2CppSharedGenericCallCatalog.fromScript(data(entries));
            throw new AssertionError(label);
        }
        catch (IOException expected) {
            // Expected.
        }
    }

    private static void expectDecodeFailure(byte[] encoded, String label) throws Exception {
        try {
            Il2CppSharedGenericCallCodec.decode(encoded);
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
