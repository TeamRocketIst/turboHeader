package turboheader.il2cpp;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

public final class Il2CppAnalysisProfile {
    private static final List<String> ANALYZERS = List.of(
            "AARCH64 ELF PLT Thunks",
            "ARM Constant Reference Analyzer",
            "Subroutine References",
            "Shared Return Calls",
            "Reference",
            "ELF Scalar Operand References",
            "External Entry References",
            "Call-Fixup Installer",
            "Non-Returning Functions - Known");

    private static final Map<String, Boolean> BOOLEAN_OPTIONS = Map.ofEntries(
            Map.entry("Subroutine References.Create Thunks Early", true),
            Map.entry("Shared Return Calls.Assume Contiguous Functions Only", true),
            Map.entry("Shared Return Calls.Allow Conditional Jumps", false),
            Map.entry("Reference.Subroutine References", true),
            Map.entry("Reference.Create Address Tables", false),
            Map.entry("Reference.Switch Table References", false),
            Map.entry("ELF Scalar Operand References.Relocation Table Guide", true),
            Map.entry("GCC Exception Handlers.Create Try Catch Comments", true),
            Map.entry("Non-Returning Functions - Discovered.Repair Flow Damage", true),
            Map.entry("Non-Returning Functions - Discovered.Create Analysis Bookmarks", false),
            Map.entry("Non-Returning Functions - Known.Create Analysis Bookmarks", false));

    private static final Map<String, Integer> INTEGER_OPTIONS = Map.of(
            "Non-Returning Functions - Discovered.Function Non-return Threshold", 3);

    private Il2CppAnalysisProfile() {
    }

    public static ProfileResult apply(Program program, Path noreturnSeeds) {
        Objects.requireNonNull(program, "program");
        long started = System.nanoTime();
        boolean customNoreturn = usesCustomNoreturn(program, noreturnSeeds);
        Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);

        Map<String, OptionType> available = new LinkedHashMap<>();
        for (String name : options.getOptionNames()) {
            OptionType type = options.getType(name);
            available.put(name, type);
            if (type == OptionType.BOOLEAN_TYPE) {
                options.setBoolean(name, false);
            }
        }

        List<String> requested = new ArrayList<>(ANALYZERS);
        if (!customNoreturn) {
            requested.add("Non-Returning Functions - Discovered");
        }

        List<String> enabled = new ArrayList<>();
        List<String> unavailable = new ArrayList<>();
        for (String name : requested) {
            if (available.get(name) == OptionType.BOOLEAN_TYPE) {
                options.setBoolean(name, true);
                enabled.add(name);
            }
            else {
                unavailable.add(name);
            }
        }

        for (var entry : BOOLEAN_OPTIONS.entrySet()) {
            if (available.get(entry.getKey()) == OptionType.BOOLEAN_TYPE) {
                options.setBoolean(entry.getKey(), entry.getValue());
            }
        }
        for (var entry : INTEGER_OPTIONS.entrySet()) {
            if (available.get(entry.getKey()) == OptionType.INT_TYPE) {
                options.setInt(entry.getKey(), entry.getValue());
            }
        }

        AutoAnalysisManager.getAnalysisManager(program).initializeOptions();
        return new ProfileResult(enabled, unavailable, customNoreturn,
                System.nanoTime() - started);
    }

    static boolean usesCustomNoreturn(Program program, Path noreturnSeeds) {
        if (noreturnSeeds != null) {
            return true;
        }
        String processor = program.getLanguage().getProcessor().toString();
        return processor.equalsIgnoreCase("AARCH64");
    }

    public record ProfileResult(List<String> enabledAnalyzers,
            List<String> unavailableAnalyzers, boolean customNoreturn,
            long elapsedNanos) {
        public ProfileResult {
            enabledAnalyzers = List.copyOf(enabledAnalyzers);
            unavailableAnalyzers = List.copyOf(unavailableAnalyzers);
            if (elapsedNanos < 0) {
                throw new IllegalArgumentException("elapsedNanos must not be negative");
            }
        }

        public double elapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }
}
