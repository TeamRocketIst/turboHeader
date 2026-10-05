// @category Test

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import com.google.gson.JsonParser;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Structure;
import turboheader.il2cpp.Il2CppLayoutPolicy;
import turboheader.il2cpp.Il2CppMetadataImportService;
import turboheader.il2cpp.NativeIl2CppTypeImportStrategy;
import turboheader.il2cpp.metadata.RuntimeLayoutStore;
import turboheader.il2cpp.types.GhidraTypeImporter;

public class VerifyTurboHeaderRuntimeLayoutImport extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        Path header = Path.of(args[0]);
        Path original = Path.of(args[1]);
        Path offsets = Files.createTempFile("runtime-layout-offsets", ".json");
        Path script = Files.createTempFile("runtime-layout-script", ".json");
        var importer = new NativeIl2CppTypeImportStrategy(currentProgram, monitor, this::println, this::printerr);
        String marker = "{\"status\":\"familyFallback\",\"profile\":\"legacy\",\"pointerSize\":8,\"runtimeFieldsVerified\":false}";
        try {
            var json = JsonParser.parseString(Files.readString(original)).getAsJsonObject();
            json.add("runtimeLayout", JsonParser.parseString(marker));
            Files.writeString(offsets, json.toString());
            importer.importTypes(header, offsets, 8, Il2CppLayoutPolicy.ALLOW_INFERRED);
            require(!RuntimeLayoutStore.allowsProofs(currentProgram), "offset confidence was ignored");
            var type = currentProgram.getDataTypeManager().getDataType(new DataTypePath(GhidraTypeImporter.ROOT, "Derived_o"));
            require(type instanceof Structure && type.getLength() == 60, "managed fields changed with fallback confidence");

            var metadata = new Il2CppMetadataImportService(currentProgram, monitor, this::println, this::printerr);
            Files.writeString(script, "{\"ScriptMethod\":[],\"RuntimeLayout\":" + marker + "}");
            metadata.importScript(script);
            require(!RuntimeLayoutStore.allowsProofs(currentProgram), "script import erased offset confidence");
            Files.writeString(script, "{\"ScriptMethod\":[],\"RuntimeLayout\":" +
                    marker.replace("familyFallback", "verified").replace("false", "true") + "}");
            try {
                metadata.importScript(script);
                throw new AssertionError("conflicting script confidence accepted");
            }
            catch (IOException expected) {
                require(!RuntimeLayoutStore.allowsProofs(currentProgram), "failed import changed confidence");
            }
            importer.importTypes(header, original, 8, Il2CppLayoutPolicy.ALLOW_INFERRED);
            require(RuntimeLayoutStore.allowsProofs(currentProgram), "legacy reimport retained stale confidence");
            println("TurboHeader runtime layout import verification passed");
        }
        finally {
            Files.deleteIfExists(offsets);
            Files.deleteIfExists(script);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
