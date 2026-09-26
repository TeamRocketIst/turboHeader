package turboheader.il2cpp.metadata;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

public final class Il2CppInterfaceDispatchCatalogTest {
    public static void main(String[] args) throws Exception {
        var method = new ScriptMethodReader.ScriptMethod(0x1100, "Sample$$Run",
                "void Sample__Run (Sample_o* self);", "vp", "Sample");
        var receiver = new ScriptMethodReader.ScriptMetadata(
                0x2100, "Sample_TypeInfo", "Sample_c*", 4);
        var interfaceType = new ScriptMethodReader.ScriptMetadata(
                0x2200, "IRunnable_TypeInfo", "IRunnable_c*", 2);
        var row = new ScriptMethodReader.ScriptInterfaceDispatch(
                4, 2, 0, 0x1100, method.signature());
        var script = data(List.of(method), List.of(receiver, interfaceType), List.of(row));

        var catalog = Il2CppInterfaceDispatchCatalog.fromScript(script).orElseThrow();
        check(catalog.typeIdsByMetadataAddress().size() == 2, "type identity count");
        var key = new Il2CppInterfaceDispatchCatalog.DispatchKey(4, 2, 0);
        check(catalog.methodAddresses().get(key) == 0x1100, "dispatch target");
        check(catalog.methodAddress(4, 2, 0).orElseThrow() == 0x1100,
                "dispatch lookup");
        check(catalog.methodAddress(4, 2, 1).isEmpty(), "missing dispatch lookup");

        byte[] encoded = Il2CppInterfaceDispatchCodec.encode(catalog);
        var restored = Il2CppInterfaceDispatchCodec.decode(encoded);
        check(restored.typeIdsByMetadataAddress().equals(
                catalog.typeIdsByMetadataAddress()), "stored type identities");
        check(restored.methodAddresses().equals(catalog.methodAddresses()),
                "stored dispatch entries");

        var absent = new ScriptMethodReader.ScriptData(
                List.of(method), List.of(receiver), List.of(), List.of());
        check(Il2CppInterfaceDispatchCatalog.fromScript(absent).isEmpty(),
                "absent table remains disabled");

        expectFailure(data(List.of(method), List.of(receiver), List.of(row)),
                "unknown interface TypeId");
        var alias = new ScriptMethodReader.ScriptMethod(0x1100, "Sample$$Alias",
                method.signature(), "vp", "Sample");
        expectFailure(data(List.of(method, alias), List.of(receiver, interfaceType),
                List.of(row)), "ambiguous method address");
        var wrongSignature = new ScriptMethodReader.ScriptInterfaceDispatch(
                4, 2, 0, 0x1100, "void Sample__Other (Sample_o* self);");
        expectFailure(data(List.of(method), List.of(receiver, interfaceType),
                List.of(wrongSignature)), "signature mismatch");
        var conflict = new ScriptMethodReader.ScriptInterfaceDispatch(
                4, 2, 0, 0x2200, method.signature());
        var secondMethod = new ScriptMethodReader.ScriptMethod(0x2200, "Sample$$Second",
                method.signature(), "vp", "Sample");
        expectFailure(data(List.of(method, secondMethod), List.of(receiver, interfaceType),
                List.of(row, conflict)), "conflicting tuple");

        byte[] trailing = java.util.Arrays.copyOf(encoded, encoded.length + 1);
        try {
            Il2CppInterfaceDispatchCodec.decode(trailing);
            throw new AssertionError("trailing stored data");
        }
        catch (IOException expected) {
            // Expected.
        }

        System.out.println("interface dispatch catalogue tests passed");
    }

    private static ScriptMethodReader.ScriptData data(
            List<ScriptMethodReader.ScriptMethod> methods,
            List<ScriptMethodReader.ScriptMetadata> metadata,
            List<ScriptMethodReader.ScriptInterfaceDispatch> dispatch) {
        return new ScriptMethodReader.ScriptData(methods, metadata, List.of(), List.of(),
                Optional.of(dispatch));
    }

    private static void expectFailure(ScriptMethodReader.ScriptData script, String label)
            throws Exception {
        try {
            Il2CppInterfaceDispatchCatalog.fromScript(script);
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
