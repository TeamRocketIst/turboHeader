package turboheader.il2cpp;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import java.util.Set;

/** Pure conservative CFG proof used only when an external i2c seed artifact is unavailable. */
final class NoreturnProofEngine {
    private static final int MAX_INSTRUCTIONS = 20_000;
    private static final long HELPER_LOCAL_SPAN = 0x4000L;
    private static final long INSTRUCTION_SIZE = 4;

    interface WordSource {
        OptionalInt read(long address);
    }

    record Discovery(Set<Long> proven, Set<Long> provenHelpers, int helperSummaries,
            long managedInstructions, long helperInstructions) {
    }

    private final WordSource words;
    private final Set<Long> managedMethods;
    private final Set<Long> terminalLeaves;
    private final Aarch64ControlFlowDecoder decoder = new Aarch64ControlFlowDecoder();
    private final Map<Long, Boolean> helperSummaries = new HashMap<>();
    private final Set<Long> activeHelpers = new HashSet<>();
    private long managedInstructions;
    private long helperInstructions;

    NoreturnProofEngine(WordSource words, Set<Long> managedMethods, Set<Long> terminalLeaves) {
        this.words = words;
        this.managedMethods = Set.copyOf(managedMethods);
        this.terminalLeaves = Set.copyOf(terminalLeaves);
    }

    Discovery discover() {
        List<Long> ordered = new ArrayList<>(managedMethods);
        ordered.sort(Long::compareUnsigned);
        for (long method : ordered) {
            scanManagedMethod(method);
        }
        Set<Long> proven = new HashSet<>(terminalLeaves);
        Set<Long> provenHelpers = new HashSet<>();
        helperSummaries.forEach((address, value) -> {
            if (value) {
                proven.add(address);
                provenHelpers.add(address);
            }
        });
        return new Discovery(Set.copyOf(proven), Set.copyOf(provenHelpers),
                helperSummaries.size(), managedInstructions, helperInstructions);
    }

    private void scanManagedMethod(long entry) {
        Set<Long> seen = new HashSet<>();
        ArrayDeque<Long> work = new ArrayDeque<>();
        work.push(entry);
        while (!work.isEmpty()) {
            long address = work.pop();
            if (!seen.add(address)) {
                continue;
            }
            if (seen.size() > MAX_INSTRUCTIONS) {
                return;
            }
            if (address != entry && managedMethods.contains(address)) {
                continue;
            }
            OptionalInt encoded = words.read(address);
            managedInstructions++;
            if (encoded.isEmpty()) {
                continue;
            }
            var instruction = decoder.decode(address, encoded.getAsInt());
            switch (instruction.kind()) {
                case DIRECT_CALL -> {
                    boolean pathEnds = !managedMethods.contains(instruction.target()) &&
                            proveHelper(instruction.target(), new Budget());
                    if (!pathEnds) {
                        pushNext(address, work);
                    }
                }
                case INDIRECT_CALL, OTHER -> pushNext(address, work);
                case DIRECT_JUMP -> {
                    long target = instruction.target();
                    OptionalInt previous = address >= entry + INSTRUCTION_SIZE
                            ? words.read(address - INSTRUCTION_SIZE) : OptionalInt.empty();
                    boolean tailBoundary = target != entry &&
                            (managedMethods.contains(target) ||
                            previous.isPresent() && decoder.isAbiTailTeardown(previous.getAsInt()));
                    if (!tailBoundary) {
                        work.push(target);
                    }
                }
                case CONDITIONAL_BRANCH -> {
                    work.push(instruction.target());
                    pushNext(address, work);
                }
                case INDIRECT_JUMP, RETURN, EXCEPTION -> {
                    // The path ends or cannot be resolved. Neither can reveal a direct helper call.
                }
            }
        }
    }

    private boolean proveHelper(long entry, Budget budget) {
        if (terminalLeaves.contains(entry)) {
            return true;
        }
        if (managedMethods.contains(entry)) {
            return false;
        }
        Boolean cached = helperSummaries.get(entry);
        if (cached != null) {
            return cached;
        }
        if (!activeHelpers.add(entry)) {
            return false;
        }
        boolean proven = true;
        try {
            Set<Long> seen = new HashSet<>();
            ArrayDeque<Long> work = new ArrayDeque<>();
            work.push(entry);
            while (!work.isEmpty()) {
                long address = work.pop();
                if (!seen.add(address)) {
                    continue;
                }
                if (++budget.instructions > MAX_INSTRUCTIONS) {
                    proven = false;
                    break;
                }
                OptionalInt encoded = words.read(address);
                helperInstructions++;
                if (encoded.isEmpty()) {
                    proven = false;
                    break;
                }
                var instruction = decoder.decode(address, encoded.getAsInt());
                switch (instruction.kind()) {
                    case DIRECT_CALL -> {
                        if (!targetNeverReturns(instruction.target(), budget)) {
                            pushNext(address, work);
                        }
                    }
                    case INDIRECT_CALL, OTHER, EXCEPTION -> pushNext(address, work);
                    case DIRECT_JUMP -> {
                        long target = instruction.target();
                        if (isLocal(entry, target)) {
                            work.push(target);
                        }
                        else if (!targetNeverReturns(target, budget)) {
                            proven = false;
                        }
                    }
                    case CONDITIONAL_BRANCH -> {
                        work.push(instruction.target());
                        pushNext(address, work);
                    }
                    case INDIRECT_JUMP, RETURN -> proven = false;
                }
                if (!proven) {
                    break;
                }
            }
        }
        finally {
            activeHelpers.remove(entry);
        }
        helperSummaries.put(entry, proven);
        return proven;
    }

    private boolean targetNeverReturns(long target, Budget budget) {
        return terminalLeaves.contains(target) ||
                !managedMethods.contains(target) && proveHelper(target, budget);
    }

    private boolean isLocal(long entry, long target) {
        return Long.compareUnsigned(target, entry) >= 0 &&
                Long.compareUnsigned(target, entry + HELPER_LOCAL_SPAN) < 0;
    }

    private void pushNext(long address, ArrayDeque<Long> work) {
        if (address <= Long.MAX_VALUE - INSTRUCTION_SIZE) {
            work.push(address + INSTRUCTION_SIZE);
        }
    }

    private static final class Budget {
        private int instructions;
    }
}
