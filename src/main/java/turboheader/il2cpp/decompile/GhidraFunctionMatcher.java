package turboheader.il2cpp.decompile;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import turboheader.il2cpp.Il2CppClassCatalog;

public final class GhidraFunctionMatcher {
    private GhidraFunctionMatcher() {
    }

    public static MatchResult match(Program program,
            List<Il2CppClassCatalog.ClassEntry> classes, TaskMonitor taskMonitor)
            throws CancelledException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(classes, "classes");
        TaskMonitor monitor = taskMonitor == null ? TaskMonitor.DUMMY : taskMonitor;
        List<Il2CppFunctionMatcher.FunctionIdentity> identities = new ArrayList<>();
        Map<Il2CppFunctionMatcher.FunctionIdentity, Function> functions =
                new IdentityHashMap<>();

        var iterator = program.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Function function = iterator.next();
            String simpleName = function.getName();
            String fullName = fullName(function, simpleName);
            var identity = new Il2CppFunctionMatcher.FunctionIdentity(
                    function.getEntryPoint().getUnsignedOffset(), fullName, simpleName,
                    function.getComment());
            identities.add(identity);
            functions.put(identity, function);
        }

        var matched = Il2CppFunctionMatcher.match(classes, identities);
        Map<Il2CppClassCatalog.ClassEntry, List<Function>> functionsByClass =
                new LinkedHashMap<>();
        matched.functionsByClass().forEach((entry, matches) -> {
            List<Function> original = new ArrayList<>(matches.size());
            for (var identity : matches) {
                Function function = functions.get(identity);
                if (function == null) {
                    throw new IllegalStateException("matched function identity was not retained");
                }
                original.add(function);
            }
            functionsByClass.put(entry, List.copyOf(original));
        });

        return new MatchResult(
                Collections.unmodifiableMap(functionsByClass),
                matched.ambiguities(),
                matched.scannedFunctions(),
                matched.matchedFunctions(),
                matched.assemblyAmbiguitiesResolved(),
                matched.assemblyMismatchesSkipped());
    }

    private static String fullName(Function function, String fallback) {
        Symbol symbol = function.getSymbol();
        if (symbol == null) {
            return fallback;
        }
        String name = symbol.getName(true);
        return name == null || name.isEmpty() ? fallback : name;
    }

    public record MatchResult(
            Map<Il2CppClassCatalog.ClassEntry, List<Function>> functionsByClass,
            List<Il2CppFunctionMatcher.Ambiguity> ambiguities, int scannedFunctions,
            int matchedFunctions, int assemblyAmbiguitiesResolved,
            int assemblyMismatchesSkipped) {
    }
}
