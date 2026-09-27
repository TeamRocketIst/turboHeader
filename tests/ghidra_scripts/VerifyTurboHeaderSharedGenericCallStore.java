// Verifies that shared-generic facts survive a project reopen.
// @category Test

import java.util.List;
import java.util.Optional;

import ghidra.app.script.GhidraScript;
import turboheader.il2cpp.metadata.Il2CppSharedGenericCallCatalog;
import turboheader.il2cpp.metadata.Il2CppSharedGenericCallStore;
import turboheader.il2cpp.metadata.ScriptMethodReader;

public class VerifyTurboHeaderSharedGenericCallStore extends GhidraScript {
    private static final long METHOD_INFO = 0x580;
    private static final long METHOD_INFO_ONE_ARG = 0x5C0;
    private static final long METHOD_INFO_THREE_ARGS = 0x620;
    private static final long METHOD = 0x560;
    private static final String SIGNATURE =
            "void shared_generic_call (Fixture_List_o* __this, int32_t index, " +
            "Il2CppObject** __result, const MethodInfo* method);";
    private static final String ONE_ARG_SIGNATURE =
            "void shared_generic_call (Il2CppObject* __this, " +
            "Il2CppObject** __result, const MethodInfo* method);";
    private static final String THREE_ARG_SIGNATURE =
            "void shared_generic_call (Il2CppObject* __this, System_String_o* name, " +
            "System_Object_array* args, Il2CppObject** __result, " +
            "const MethodInfo* method);";

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length > 1 || (args.length == 1 && !args[0].equals("write"))) {
            throw new IllegalArgumentException("Expected: [write]");
        }
        long blockOffset = currentProgram.getMemory().getBlock("interface_dispatch")
                .getStart().subtract(currentProgram.getImageBase());
        long methodInfo = Math.addExact(blockOffset, METHOD_INFO);
        long methodInfoOneArg = Math.addExact(blockOffset, METHOD_INFO_ONE_ARG);
        long methodInfoThreeArgs = Math.addExact(blockOffset, METHOD_INFO_THREE_ARGS);
        long method = Math.addExact(blockOffset, METHOD);
        if (args.length == 1) {
            var rows = List.of(
                    new ScriptMethodReader.ScriptSharedGenericCall(
                            methodInfo, method, SIGNATURE),
                    new ScriptMethodReader.ScriptSharedGenericCall(
                            methodInfoOneArg, method, ONE_ARG_SIGNATURE),
                    new ScriptMethodReader.ScriptSharedGenericCall(
                            methodInfoThreeArgs, method, THREE_ARG_SIGNATURE));
            var data = new ScriptMethodReader.ScriptData(
                    List.of(), List.of(), List.of(), List.of(), Optional.empty(),
                    Optional.empty(), Optional.of(rows));
            Il2CppSharedGenericCallStore.replace(currentProgram,
                    Il2CppSharedGenericCallCatalog.fromScript(data));
        }

        var catalog = Il2CppSharedGenericCallStore.read(currentProgram).orElseThrow();
        require(catalog.entries().size() == 3, "shared-generic entry count");
        require(catalog.forMethodInfoAddress(methodInfo).orElseThrow()
                .methodAddress() == method, "shared-generic lookup");
        require(catalog.forMethodInfoAddress(methodInfoOneArg).orElseThrow()
                .methodAddress() == method, "one-argument shared-generic lookup");
        require(catalog.forMethodInfoAddress(methodInfoThreeArgs).orElseThrow()
                .methodAddress() == method, "three-argument shared-generic lookup");
        println(args.length == 1
                ? "TurboHeader shared-generic catalogue stored"
                : "TurboHeader shared-generic catalogue survived project reopen");
        if (args.length == 0) {
            Il2CppSharedGenericCallStore.replace(currentProgram, Optional.empty());
            require(Il2CppSharedGenericCallStore.read(currentProgram).isEmpty(),
                    "absent shared-generic catalogue clears stored facts");
            println("TurboHeader absent shared-generic catalogue cleared stored facts");
        }
    }

    private static void require(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }
}
