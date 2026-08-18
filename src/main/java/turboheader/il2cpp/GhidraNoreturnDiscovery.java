package turboheader.il2cpp;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.OptionalInt;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

/** Adapts Ghidra program memory and symbols to the pure conservative proof engine. */
final class GhidraNoreturnDiscovery {
    private static final Set<String> TERMINAL_NAMES = Set.of(
            "abort", "exit", "_exit", "_Exit", "__assert", "__assert2",
            "__assert_fail", "__stack_chk_fail", "__cxa_throw", "__cxa_rethrow",
            "__cxa_throw_bad_array_new_length", "_Unwind_Resume", "longjmp",
            "siglongjmp", "pthread_exit", "_ZSt9terminatev", "_ZSt10unexpectedv");

    private final Program program;
    private final Address imageBase;

    GhidraNoreturnDiscovery(Program program) {
        this.program = program;
        this.imageBase = program.getImageBase();
    }

    NoreturnProofEngine.Discovery discover(Set<Long> managedMethods) {
        Set<Long> terminals = terminalLeaves();
        if (terminals.isEmpty()) {
            throw new IllegalStateException(
                    "No executable terminal PLT thunks were resolved; run the ELF PLT thunk analyzer first");
        }
        return new NoreturnProofEngine(this::readWord, managedMethods, terminals).discover();
    }

    private Set<Long> terminalLeaves() {
        ensureAarch64();
        return Set.copyOf(resolveExecutableTerminalThunks());
    }

    private void ensureAarch64() {
        String processor = program.getLanguage().getProcessor().toString();
        if (!processor.equalsIgnoreCase("AARCH64")) {
            throw new IllegalStateException(
                    "TurboHeader noreturn discovery currently supports AARCH64, not " + processor);
        }
    }

    private Set<Long> resolveExecutableTerminalThunks() {
        Set<Long> result = new HashSet<>();
        var functions = program.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            Address entry = function.getEntryPoint();
            var block = program.getMemory().getBlock(entry);
            if (function.isExternal() || block == null || !block.isExecute()) {
                continue;
            }
            boolean terminal = matchesTerminal(function);
            Function thunkTarget = function.isThunk() ? function.getThunkedFunction(true) : null;
            if (!terminal && thunkTarget != null) {
                terminal = matchesTerminal(thunkTarget);
            }
            boolean isPlt = block.getName().toLowerCase(Locale.ROOT).contains("plt");
            if (terminal && (function.isThunk() || isPlt)) {
                result.add(entry.subtract(imageBase));
            }
        }
        return result;
    }

    private boolean matchesTerminal(Function function) {
        if (function == null) {
            return false;
        }
        return TERMINAL_NAMES.contains(normalize(function.getName())) ||
                TERMINAL_NAMES.contains(normalize(function.getName(true)));
    }

    private String normalize(String name) {
        String value = name == null ? "" : name.trim();
        int namespace = value.lastIndexOf("::");
        if (namespace >= 0) {
            value = value.substring(namespace + 2);
        }
        for (String prefix : List.of("sym.imp.", "imp.", "thunk_", "j_")) {
            if (value.startsWith(prefix)) {
                value = value.substring(prefix.length());
            }
        }
        int version = value.indexOf('@');
        if (version >= 0) {
            value = value.substring(0, version);
        }
        if (value.endsWith("()")) {
            value = value.substring(0, value.length() - 2);
        }
        return value;
    }

    private OptionalInt readWord(long rawAddress) {
        try {
            Address address = imageBase.add(rawAddress);
            var block = program.getMemory().getBlock(address);
            if (block == null || !block.isExecute()) {
                return OptionalInt.empty();
            }
            return OptionalInt.of(program.getMemory().getInt(address));
        }
        catch (MemoryAccessException | RuntimeException e) {
            return OptionalInt.empty();
        }
    }
}
