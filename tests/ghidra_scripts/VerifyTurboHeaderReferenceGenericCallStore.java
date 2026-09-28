// Verifies reference-return catalog persistence without applying prototypes.
// @category Test

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import turboheader.il2cpp.Il2CppMetadataImportService;
import turboheader.il2cpp.metadata.Il2CppReferenceGenericCallCatalog;
import turboheader.il2cpp.metadata.Il2CppReferenceGenericCallStore;
import turboheader.il2cpp.metadata.Il2CppSharedGenericCallStore;
import turboheader.il2cpp.metadata.ScriptMethodReader;

public class VerifyTurboHeaderReferenceGenericCallStore extends GhidraScript {
    private static final String SIGNATURE =
            "Sample_Item_o* reference_generic_call (Sample_Box_o* __this, int32_t arg1, const MethodInfo* method);";
    private static final String OPTIONS = "TurboHeader IL2CPP";
    private static final String KEY = "Reference Generic Call Catalogue";
    private static final String JSON = "{\"ScriptMethod\":[],\"ScriptReferenceGenericCall\":[" +
            "{\"MethodInfoAddress\":256,\"MethodSpecIndex\":7,\"MethodAddress\":768,\"Signature\":\"" +
            SIGNATURE + "\"}]}";

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        require(args.length == 0 || args.length == 1 && args[0].equals("write"), "expected [write]");
        if (args.length == 1) {
            // Establish the ordinary importer's base types before measuring catalog-only changes.
            importJson("{\"ScriptMethod\":[]}");
        }
        int functions = currentProgram.getFunctionManager().getFunctionCount();
        int types = currentProgram.getDataTypeManager().getDataTypeCount(true);
        byte[] code = new byte[32];
        var start = currentProgram.getMemory().getBlock("interface_dispatch").getStart();
        currentProgram.getMemory().getBytes(start, code);
        if (args.length == 1) {
            importJson(JSON);
            println("TurboHeader reference-generic catalogue stored");
        }
        var catalog = Il2CppReferenceGenericCallStore.read(currentProgram).orElseThrow();
        require(catalog.entries().equals(List.of(new Il2CppReferenceGenericCallCatalog.Entry(
                256, 7, 768, SIGNATURE))), "stored facts differ");
        verifyRollback(catalog);
        if (args.length == 0) {
            println("TurboHeader reference-generic catalogue survived project reopen");
        }

        byte[] before = currentProgram.getOptions(OPTIONS).getByteArray(KEY, null);
        var options = currentProgram.getOptions(OPTIONS);
        try {
            options.setByteArray(KEY, new byte[] {1, 2, 3});
            expectStoredFailure();
            require(Arrays.equals(options.getByteArray(KEY, null), new byte[] {1, 2, 3}),
                    "read silently repaired corrupt bytes");
            options.removeOption(KEY);
            options.setString(KEY, "invalid");
            expectStoredFailure();
            require(options.getString(KEY, null).equals("invalid"), "read changed wrong-type option");
        }
        finally {
            options.removeOption(KEY);
            options.setByteArray(KEY, before);
        }
        for (String invalid : List.of(JSON.replace("\"MethodSpecIndex\":7", "\"MethodSpecIndex\":-1"),
                JSON.replace("\"Signature\":", "\"MethodSpecIndex\":8,\"Signature\":"),
                JSON.replace("Sample_Item_o*", "void"))) {
            try {
                importJson(invalid);
                throw new AssertionError("invalid import accepted");
            }
            catch (IOException expected) {
                require(Arrays.equals(before, currentProgram.getOptions(OPTIONS).getByteArray(KEY, null)),
                        "failed import changed stored facts");
            }
        }

        if (args.length == 0) {
            var legacy = Il2CppSharedGenericCallStore.read(currentProgram);
            var empty = new ScriptMethodReader.ScriptData(List.of(), List.of(), List.of(), List.of(),
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(List.of()));
            Il2CppReferenceGenericCallStore.replace(currentProgram,
                    Il2CppReferenceGenericCallCatalog.fromScript(empty));
            require(Il2CppReferenceGenericCallStore.read(currentProgram).orElseThrow().entries().isEmpty(),
                    "empty catalog must remain present");
            Il2CppReferenceGenericCallStore.replace(currentProgram, Optional.empty());
            require(Il2CppReferenceGenericCallStore.read(currentProgram).isEmpty(), "absent catalog must clear");
            require(Il2CppSharedGenericCallStore.read(currentProgram).map(value -> value.entries())
                    .equals(legacy.map(value -> value.entries())), "legacy catalog changed");
            println("TurboHeader reference-generic catalogue rejection and clearing verified");
        }
        byte[] after = new byte[code.length];
        currentProgram.getMemory().getBytes(start, after);
        require(Arrays.equals(code, after), "catalog import changed code");
        require(currentProgram.getFunctionManager().getFunctionCount() == functions, "catalog import created functions");
        require(currentProgram.getDataTypeManager().getDataTypeCount(true) == types, "catalog import created types");
    }

    private void importJson(String json) throws Exception {
        Path path = Files.createTempFile("reference-catalog-", ".json");
        try {
            Files.writeString(path, json);
            new Il2CppMetadataImportService(currentProgram, monitor, this::println, this::printerr).importScript(path);
        }
        finally {
            Files.deleteIfExists(path);
        }
    }

    private void expectStoredFailure() throws Exception {
        try {
            Il2CppReferenceGenericCallStore.read(currentProgram);
            throw new AssertionError("corrupt stored catalog treated as absent");
        }
        catch (IOException expected) {
            // Corrupt storage is not an absent optional table.
        }
    }

    private void verifyRollback(Il2CppReferenceGenericCallCatalog catalog) throws Exception {
        var program = new ProgramDB("reference-catalog-rollback", currentProgram.getLanguage(),
                currentProgram.getLanguage().getDefaultCompilerSpec(), this);
        try {
            Il2CppReferenceGenericCallStore.replace(program, Optional.of(catalog));
            int transaction = program.startTransaction("abort catalog replacement");
            try {
                Il2CppReferenceGenericCallStore.replace(program, Optional.empty());
                require(Il2CppReferenceGenericCallStore.read(program).isEmpty(), "clear inside transaction");
            }
            finally {
                program.endTransaction(transaction, false);
            }
            require(Il2CppReferenceGenericCallStore.read(program).orElseThrow().entries()
                    .equals(catalog.entries()), "rollback lost previous catalog");
        }
        finally {
            program.release(this);
        }
    }

    private static void require(boolean condition, String label) {
        if (!condition) throw new AssertionError(label);
    }
}
