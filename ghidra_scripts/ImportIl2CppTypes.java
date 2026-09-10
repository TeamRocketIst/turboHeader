// Imports IL2CPP Dumper C structures into the current Ghidra program using a native parser.
// @category Data Types

import java.io.File;
import java.nio.file.Path;

import ghidra.app.script.GhidraScript;
import turboheader.il2cpp.HeadlessRequestReader;
import turboheader.il2cpp.Il2CppLayoutPolicy;
import turboheader.il2cpp.Il2CppMetadataImportService;
import turboheader.il2cpp.NativeIl2CppTypeImportStrategy;

public class ImportIl2CppTypes extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("Open a program before running this importer.");
            return;
        }

        String[] args = getScriptArgs();
        boolean requestMode = args.length > 0 && args[0].equals("--request");
        if (requestMode && args.length != 2) {
            throw new IllegalArgumentException("Expected: --request <import-request.json>");
        }
        if (!requestMode && args.length > 4) {
            throw new IllegalArgumentException(
                    "Expected: il2cpp.h [type_offsets.json|dump.cs|-] " +
                    "[script.json|-] [allow-inferred|require-external-offsets|" +
                    "require-authoritative]");
        }
        Path header;
        Path offsets = null;
        Path script = null;
        int pointerSize = currentProgram.getDefaultPointerSize();
        var layoutPolicy = Il2CppLayoutPolicy.ALLOW_INFERRED;

        if (requestMode) {
            var request = HeadlessRequestReader.readImport(Path.of(args[1]));
            header = request.header();
            offsets = request.offsets();
            script = request.methods();
            layoutPolicy = layoutPolicy(request.layoutPolicy());
        }
        else if (args.length > 0) {
            header = Path.of(args[0]);
            if (args.length > 1 && !args[1].isBlank() && !args[1].equals("-")) {
                offsets = Path.of(args[1]);
            }
            if (args.length > 2 && !args[2].isBlank() && !args[2].equals("-")) {
                script = Path.of(args[2]);
            }
            if (args.length > 3) {
                layoutPolicy = layoutPolicy(args[3]);
            }
        }
        else {
            File selectedHeader = askFile("Select IL2CPP Dumper header", "Import");
            header = selectedHeader.toPath();
            if (askYesNo("IL2CPP field offsets",
                    "Use type_offsets.json or dump.cs for external field offsets?")) {
                offsets = askFile("Select type_offsets.json or dump.cs", "Import").toPath();
            }
            else if (!askYesNo("Inferred IL2CPP layout",
                    "No offset sidecar was selected. Continue with offsets inferred from il2cpp.h? " +
                    "They are not guaranteed to match the runtime layout.")) {
                return;
            }
            if (askYesNo("IL2CPP method signatures",
                    "Apply names and prototypes from script.json?")) {
                script = askFile("Select script.json", "Import").toPath();
            }
        }

        new NativeIl2CppTypeImportStrategy(currentProgram, monitor, this::println, this::printerr)
                .importTypes(header, offsets, pointerSize, layoutPolicy);

        if (script != null) {
            new Il2CppMetadataImportService(currentProgram, monitor, this::println, this::printerr)
                    .importScript(script);
        }
    }

    private static Il2CppLayoutPolicy layoutPolicy(String value) {
        return switch (value) {
            case "allow-inferred" -> Il2CppLayoutPolicy.ALLOW_INFERRED;
            case "require-external-offsets" ->
                Il2CppLayoutPolicy.REQUIRE_EXTERNAL_OFFSETS;
            case "require-authoritative" ->
                Il2CppLayoutPolicy.REQUIRE_AUTHORITATIVE;
            default -> throw new IllegalArgumentException("Unknown layout policy: " + value);
        };
    }

    private static Il2CppLayoutPolicy layoutPolicy(
            HeadlessRequestReader.LayoutPolicy value) {
        return switch (value) {
            case ALLOW_INFERRED -> Il2CppLayoutPolicy.ALLOW_INFERRED;
            case REQUIRE_EXTERNAL_OFFSETS ->
                Il2CppLayoutPolicy.REQUIRE_EXTERNAL_OFFSETS;
            case REQUIRE_AUTHORITATIVE ->
                Il2CppLayoutPolicy.REQUIRE_AUTHORITATIVE;
        };
    }
}
