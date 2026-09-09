// Exports selected IL2CPP classes through the native Java pipeline.
// @category Extraction

import java.nio.file.Path;

import ghidra.app.script.GhidraScript;
import turboheader.il2cpp.HeadlessRequestReader;
import turboheader.il2cpp.Il2CppExportPipeline;

public class ExportIl2Cpp extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("Open a program before exporting IL2CPP classes");
        }

        String[] args = getScriptArgs();
        if (args.length != 2 || !args[0].equals("--request")) {
            throw new IllegalArgumentException(
                    "Expected: --request <export-request.json>");
        }

        var request = HeadlessRequestReader.readExport(Path.of(args[1]));
        var result = Il2CppExportPipeline.run(
                currentProgram, request, monitor, this::println);
        int failed = result.decompilation().failedFunctions();
        int ambiguous = result.plan().ambiguities().size();
        if (failed != 0 || ambiguous != 0) {
            throw new IllegalStateException(String.format(
                    "Export lost %d function bodies and skipped %d ambiguous functions; " +
                    "see the output reports.", failed, ambiguous));
        }
    }
}
