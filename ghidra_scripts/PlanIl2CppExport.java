// Validates and reports an IL2CPP export plan without modifying the program.
// @category Extraction

import java.nio.file.Path;

import ghidra.app.script.GhidraScript;
import turboheader.il2cpp.HeadlessRequestReader;
import turboheader.il2cpp.Il2CppExportPlanner;

public class PlanIl2CppExport extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("Open a program before planning an export");
        }

        String[] args = getScriptArgs();
        if (args.length != 2 || !args[0].equals("--request")) {
            throw new IllegalArgumentException("Expected: --request <export-request.json>");
        }

        var request = HeadlessRequestReader.readExport(Path.of(args[1]));
        long modification = currentProgram.getModificationNumber();
        var plan = Il2CppExportPlanner.plan(currentProgram, request, monitor);
        if (currentProgram.getModificationNumber() != modification) {
            throw new IllegalStateException("export planning modified the Ghidra program");
        }

        println(String.format(
                "TurboHeader export plan: discovered=%d, selected=%d, scanned=%d, " +
                "matched=%d, unmatched=%d, ambiguous=%d, assembly-resolved=%d, " +
                "assembly-mismatches=%d, jobs=%d.",
                plan.discoveredClasses(), plan.classes().size(), plan.scannedFunctions(),
                plan.matchedFunctions(), plan.unmatchedClasses().size(),
                plan.ambiguities().size(), plan.assemblyAmbiguitiesResolved(),
                plan.assemblyMismatchesSkipped(), request.decompileJobs()));
    }
}
