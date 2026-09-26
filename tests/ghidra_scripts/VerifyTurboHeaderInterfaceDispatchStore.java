// Verifies that the interface-dispatch catalogue survives a project reopen.
// @category Test

import java.util.List;
import java.util.Optional;

import ghidra.app.script.GhidraScript;
import turboheader.il2cpp.metadata.Il2CppInterfaceDispatchCatalog;
import turboheader.il2cpp.metadata.Il2CppInterfaceDispatchStore;
import turboheader.il2cpp.metadata.ScriptMethodReader;

public class VerifyTurboHeaderInterfaceDispatchStore extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length > 1 || (args.length == 1 && !args[0].equals("write"))) {
            throw new IllegalArgumentException("Expected: [write]");
        }
        if (args.length == 1) {
            Il2CppInterfaceDispatchStore.replace(currentProgram,
                    Il2CppInterfaceDispatchCatalog.fromScript(fixture()));
        }

        var catalog = Il2CppInterfaceDispatchStore.read(currentProgram).orElseThrow();
        require(catalog.typeIdsByMetadataAddress().size() == 2, "type identities");
        var key = new Il2CppInterfaceDispatchCatalog.DispatchKey(4, 2, 0);
        require(catalog.methodAddresses().get(key) == 0x40, "dispatch target");
        println(args.length == 1
                ? "TurboHeader interface-dispatch catalogue stored"
                : "TurboHeader interface-dispatch catalogue survived project reopen");
        if (args.length == 0) {
            Il2CppInterfaceDispatchStore.replace(currentProgram, Optional.empty());
            require(Il2CppInterfaceDispatchStore.read(currentProgram).isEmpty(),
                    "absent catalogue clears stored facts");
            println("TurboHeader absent interface-dispatch catalogue cleared stored facts");
        }
    }

    private static ScriptMethodReader.ScriptData fixture() {
        String signature = "void Sample__Run (Sample_o* self);";
        var method = new ScriptMethodReader.ScriptMethod(
                0x40, "Sample$$Run", signature, "vp", "Sample");
        var receiver = new ScriptMethodReader.ScriptMetadata(
                0x100, "Sample_TypeInfo", "Sample_c*", 4);
        var interfaceType = new ScriptMethodReader.ScriptMetadata(
                0x108, "IRunnable_TypeInfo", "IRunnable_c*", 2);
        var dispatch = new ScriptMethodReader.ScriptInterfaceDispatch(
                4, 2, 0, 0x40, signature);
        return new ScriptMethodReader.ScriptData(List.of(method),
                List.of(receiver, interfaceType), List.of(), List.of(),
                Optional.of(List.of(dispatch)));
    }

    private static void require(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }
}
