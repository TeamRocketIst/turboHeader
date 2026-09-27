// Verifies that delegate signatures survive a project reopen.
// @category Test

import java.util.List;
import java.util.Optional;

import ghidra.app.script.GhidraScript;
import turboheader.il2cpp.analysis.delegatecall.Il2CppDelegatePrototypeCatalog;
import turboheader.il2cpp.metadata.Il2CppDelegateSignatureCatalog;
import turboheader.il2cpp.metadata.Il2CppDelegateSignatureStore;
import turboheader.il2cpp.metadata.ScriptMethodReader;

public class VerifyTurboHeaderDelegateSignatureStore extends GhidraScript {
    private static final String OBJECT_TYPE = "System_Action_int__o*";
    private static final String SIGNATURE =
            "void delegate_invoke (Il2CppMethodPointer methodCode, int32_t value, " +
            "const MethodInfo* method);";

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length > 1 || (args.length == 1 && !args[0].equals("write"))) {
            throw new IllegalArgumentException("Expected: [write]");
        }
        if (args.length == 1) {
            Il2CppDelegateSignatureStore.replace(currentProgram,
                    Il2CppDelegateSignatureCatalog.fromScript(fixture()));
        }

        var catalog = Il2CppDelegateSignatureStore.read(currentProgram).orElseThrow();
        require(catalog.entries().size() == 2, "entry count");
        require(catalog.forTypeId(7).orElseThrow().objectType().equals(OBJECT_TYPE),
                "TypeId lookup");
        require(catalog.forTypeId(9).orElseThrow().objectType().equals(OBJECT_TYPE),
                "alias TypeId lookup");
        require(catalog.forObjectType(OBJECT_TYPE).orElseThrow().equals(SIGNATURE),
                "object type lookup");
        var prototypes = Il2CppDelegatePrototypeCatalog.read(currentProgram).orElseThrow();
        require(prototypes.size() == 2, "prototype alias count");
        require(prototypes.forTypeId(7).isPresent() && prototypes.forTypeId(9).isPresent(),
                "prototype TypeId aliases");
        require(prototypes.forObjectType(OBJECT_TYPE).orElseThrow().signature()
                .equals(SIGNATURE), "prototype object type lookup");
        println(args.length == 1
                ? "TurboHeader delegate-signature catalogue stored"
                : "TurboHeader delegate-signature catalogue survived project reopen");
        if (args.length == 0) {
            Il2CppDelegateSignatureStore.replace(currentProgram, Optional.empty());
            require(Il2CppDelegateSignatureStore.read(currentProgram).isEmpty(),
                    "absent catalogue clears stored facts");
            println("TurboHeader absent delegate-signature catalogue cleared stored facts");
        }
    }

    private static ScriptMethodReader.ScriptData fixture() {
        var first = new ScriptMethodReader.ScriptDelegateSignature(
                7, OBJECT_TYPE, SIGNATURE);
        var alias = new ScriptMethodReader.ScriptDelegateSignature(
                9, OBJECT_TYPE, SIGNATURE);
        return new ScriptMethodReader.ScriptData(List.of(), List.of(), List.of(), List.of(),
                Optional.empty(), Optional.of(List.of(first, alias)));
    }

    private static void require(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }
}
