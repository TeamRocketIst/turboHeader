package turboheader.il2cpp.analysis.architecture.aarch64;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import turboheader.il2cpp.analysis.Il2CppHelperKind;
import turboheader.il2cpp.analysis.architecture.ArchitectureHelperProof;
import turboheader.il2cpp.analysis.architecture.ControlFlowDecoder;

final class Aarch64InterfaceDispatchProof implements ArchitectureHelperProof {
    private static final int INSTRUCTION_SIZE = Integer.BYTES;
    private static final int CALLSITE_INSTRUCTIONS = 10;
    private static final int HELPER_PREFIX_INSTRUCTIONS = 12;
    private static final int INVOKE_DATA_SHIFT = 4;
    private static final int X0 = 0;
    private static final int X1 = 1;
    private static final int X2 = 2;
    private static final int LINK_REGISTER = 30;
    private static final int ZERO_REGISTER = 31;
    private static final int FIRST_CALLEE_SAVED = 19;
    private static final int LAST_CALLEE_SAVED = 28;

    private static final int MOVE_REGISTER_MASK = 0x7fe0_ffe0;
    private static final int MOVE_REGISTER = 0x2a00_03e0;
    private static final int MOVE_ZERO_32_MASK = 0xffff_ffe0;
    private static final int MOVE_ZERO_32 = 0x2a1f_03e0;
    private static final int MOVE_WIDE_32_MASK = 0x7f80_0000;
    private static final int MOVE_WIDE_32 = 0x5280_0000;
    private static final int LOAD_SIGNED_WORD_MASK = 0xffc0_0000;
    private static final int LOAD_SIGNED_WORD = 0xb980_0000;
    private static final int ADD_SHIFTED_REGISTER_MASK = 0xffe0_0000;
    private static final int ADD_SHIFTED_REGISTER = 0x8b00_0000;
    private static final int ADD_IMMEDIATE_64_MASK = 0xffc0_0000;
    private static final int ADD_IMMEDIATE_64 = 0x9100_0000;
    private static final int LOAD_PAIR_OFFSET_64_MASK = 0xffc0_0000;
    private static final int LOAD_PAIR_OFFSET_64 = 0xa940_0000;
    private static final int STORE_PAIR_PREINDEX_64_MASK = 0xffc0_03e0;
    private static final int STORE_PAIR_PREINDEX_64 = 0xa980_03e0;

    private final ControlFlowDecoder decoder = new Aarch64ControlFlowDecoder();

    @Override
    public Result analyze(Input input) {
        Map<Long, Boolean> helperValidity = new HashMap<>();
        Map<Long, Evidence> accepted = new HashMap<>();
        Set<Long> conflicts = new HashSet<>();
        int callsiteCandidates = 0;
        for (ManagedMethod method : input.methods()) {
            List<InstructionWord> instructions = method.instructions();
            for (int first = 0; first + CALLSITE_INSTRUCTIONS <= instructions.size(); first++) {
                int callIndex = first + 2;
                Optional<Evidence> match = matchCallsite(method, callIndex, input.managedMethods());
                if (match.isEmpty()) {
                    continue;
                }
                callsiteCandidates++;
                Evidence evidence = match.get();
                boolean valid = helperValidity.computeIfAbsent(evidence.helperAddress(),
                        address -> validateHelper(address, input.managedMethods(), input.words()));
                if (valid) {
                    mergeEvidence(accepted, conflicts, evidence);
                }
            }
        }
        List<Evidence> result = new ArrayList<>(accepted.values());
        result.sort(Comparator
                .comparing(Evidence::helperAddress, Long::compareUnsigned)
                .thenComparing(Evidence::witnessAddress, Long::compareUnsigned));
        int rejectedHelpers = conflicts.size() +
                (int) helperValidity.values().stream().filter(valid -> !valid).count();
        return new Result(result, callsiteCandidates, helperValidity.size(), rejectedHelpers);
    }

    private Optional<Evidence> matchCallsite(ManagedMethod method, int callIndex,
            Set<Long> managedMethods) {
        List<InstructionWord> instructions = method.instructions();
        int first = callIndex - 2;
        int last = callIndex + 7;
        if (!contiguous(instructions, first, last)) {
            return Optional.empty();
        }

        InstructionWord objectMove = instructions.get(first);
        int objectRegister = sourceRegister(objectMove.encoding());
        if (!isMove(objectMove.encoding(), X0, objectRegister, true) ||
                objectRegister == X0 || objectRegister == ZERO_REGISTER ||
                !isSlotImmediate(instructions.get(callIndex - 1).encoding())) {
            return Optional.empty();
        }

        InstructionWord call = instructions.get(callIndex);
        var decodedCall = decoder.decode(call.address(), call.encoding());
        long helperAddress = decodedCall.target();
        if (decodedCall.kind() != ControlFlowDecoder.Kind.DIRECT_CALL ||
                helperAddress == 0 || (helperAddress & 3) != 0 ||
                managedMethods.contains(helperAddress) || method.contains(helperAddress)) {
            return Optional.empty();
        }

        InstructionWord skip = instructions.get(callIndex + 1);
        var decodedSkip = decoder.decode(skip.address(), skip.encoding());
        if (decodedSkip.kind() != ControlFlowDecoder.Kind.DIRECT_JUMP ||
                decodedSkip.target() != instructions.get(callIndex + 5).address()) {
            return Optional.empty();
        }

        Long vtableOffset = fastPathOffset(instructions, callIndex);
        if (vtableOffset == null || !dispatchMatches(instructions, callIndex, objectRegister)) {
            return Optional.empty();
        }
        return Optional.of(new Evidence(Il2CppHelperKind.INTERFACE_INVOKE_LOOKUP,
                helperAddress, call.address(), vtableOffset));
    }

    private Long fastPathOffset(List<InstructionWord> instructions, int callIndex) {
        int load = instructions.get(callIndex + 2).encoding();
        int offsetRegister = load & 31;
        int offsetBase = (load >>> 5) & 31;
        if (!matches(load, LOAD_SIGNED_WORD_MASK, LOAD_SIGNED_WORD) ||
                ((load >>> 10) & 0xfff) != 0 || offsetBase == ZERO_REGISTER) {
            return null;
        }

        int scale = instructions.get(callIndex + 3).encoding();
        int scaledRegister = scale & 31;
        int scaledLeft = (scale >>> 5) & 31;
        int scaledRight = (scale >>> 16) & 31;
        if (!matches(scale, ADD_SHIFTED_REGISTER_MASK, ADD_SHIFTED_REGISTER) ||
                scaledRegister != scaledLeft || scaledRight != offsetRegister ||
                scaledRegister == scaledRight || ((scale >>> 10) & 0x3f) != INVOKE_DATA_SHIFT) {
            return null;
        }

        int entry = instructions.get(callIndex + 4).encoding();
        long vtableOffset = (entry >>> 10) & 0xfffL;
        if (!matches(entry, ADD_IMMEDIATE_64_MASK, ADD_IMMEDIATE_64) ||
                (entry & 31) != X0 || ((entry >>> 5) & 31) != scaledRegister ||
                vtableOffset == 0 || (vtableOffset & 7) != 0) {
            return null;
        }
        return vtableOffset;
    }

    private boolean dispatchMatches(List<InstructionWord> instructions, int callIndex,
            int objectRegister) {
        int loadPair = instructions.get(callIndex + 5).encoding();
        int invokeRegister = loadPair & 31;
        if (!matches(loadPair, LOAD_PAIR_OFFSET_64_MASK, LOAD_PAIR_OFFSET_64) ||
                ((loadPair >>> 5) & 31) != X0 || ((loadPair >>> 10) & 31) != X1 ||
                ((loadPair >>> 15) & 0x7f) != 0 || invokeRegister == X0 ||
                invokeRegister == X1 || invokeRegister == ZERO_REGISTER) {
            return false;
        }
        if (!isMove(instructions.get(callIndex + 6).encoding(), X0, objectRegister, true)) {
            return false;
        }
        int dispatch = instructions.get(callIndex + 7).encoding();
        return decoder.decode(instructions.get(callIndex + 7).address(), dispatch).kind() ==
                ControlFlowDecoder.Kind.INDIRECT_CALL && ((dispatch >>> 5) & 31) == invokeRegister;
    }

    private boolean validateHelper(long address, Set<Long> managedMethods,
            ExecutableWords words) {
        if (managedMethods.contains(address)) {
            return false;
        }
        int[] prefix = readPrefix(address, words);
        if (prefix == null || !savesLinkRegister(prefix[0])) {
            return false;
        }

        int savedObject = -1;
        int savedInterface = -1;
        int savedSlot = -1;
        boolean nativeCall = false;
        boolean conditionSeen = false;
        boolean conditional = false;
        for (int index = 1; index < prefix.length; index++) {
            long instructionAddress = address + (long) index * INSTRUCTION_SIZE;
            int encoding = prefix[index];
            if (isMoveRegister(encoding)) {
                int destination = encoding & 31;
                int source = sourceRegister(encoding);
                if (isCalleeSaved(destination)) {
                    if (source == X0 && is64Bit(encoding)) {
                        savedObject = destination;
                    }
                    else if (source == X1 && is64Bit(encoding)) {
                        savedInterface = destination;
                    }
                    else if (source == X2 && !is64Bit(encoding)) {
                        savedSlot = destination;
                    }
                }
            }

            var decoded = decoder.decode(instructionAddress, encoding);
            if (decoded.kind() == ControlFlowDecoder.Kind.DIRECT_CALL &&
                    decoded.target() != address && !managedMethods.contains(decoded.target()) &&
                    words.isExecutable(decoded.target())) {
                nativeCall = true;
            }
            if (!conditionSeen && decoded.kind() == ControlFlowDecoder.Kind.CONDITIONAL_BRANCH) {
                conditionSeen = true;
                long fallthrough = instructionAddress + INSTRUCTION_SIZE;
                conditional = words.isExecutable(decoded.target()) &&
                        words.isExecutable(fallthrough);
            }
        }
        return savedObject >= 0 && savedInterface >= 0 && savedSlot >= 0 &&
                savedObject != savedInterface && savedObject != savedSlot &&
                savedInterface != savedSlot && nativeCall && conditional;
    }

    private int[] readPrefix(long address, ExecutableWords words) {
        int[] result = new int[HELPER_PREFIX_INSTRUCTIONS];
        for (int index = 0; index < result.length; index++) {
            long delta = (long) index * INSTRUCTION_SIZE;
            long current = address + delta;
            if (Long.compareUnsigned(current, address) < 0 || !words.isExecutable(current)) {
                return null;
            }
            var encoding = words.read(current);
            if (encoding.isEmpty()) {
                return null;
            }
            result[index] = encoding.getAsInt();
        }
        return result;
    }

    private void mergeEvidence(Map<Long, Evidence> accepted, Set<Long> conflicts,
            Evidence evidence) {
        long address = evidence.helperAddress();
        if (conflicts.contains(address)) {
            return;
        }
        Evidence previous = accepted.putIfAbsent(address, evidence);
        if (previous == null) {
            return;
        }
        if (previous.layoutOffset() != evidence.layoutOffset()) {
            accepted.remove(address);
            conflicts.add(address);
        }
        else if (Long.compareUnsigned(evidence.witnessAddress(), previous.witnessAddress()) < 0) {
            accepted.put(address, evidence);
        }
    }

    private boolean contiguous(List<InstructionWord> instructions, int first, int last) {
        for (int index = first + 1; index <= last; index++) {
            long previous = instructions.get(index - 1).address();
            long next = previous + INSTRUCTION_SIZE;
            if (Long.compareUnsigned(next, previous) < 0 ||
                    instructions.get(index).address() != next) {
                return false;
            }
        }
        return true;
    }

    private boolean savesLinkRegister(int encoding) {
        return matches(encoding, STORE_PAIR_PREINDEX_64_MASK, STORE_PAIR_PREINDEX_64) &&
                ((encoding & 31) == LINK_REGISTER ||
                ((encoding >>> 10) & 31) == LINK_REGISTER);
    }

    private boolean isSlotImmediate(int encoding) {
        if (matches(encoding, MOVE_ZERO_32_MASK, MOVE_ZERO_32)) {
            return (encoding & 31) == X2;
        }
        return matches(encoding, MOVE_WIDE_32_MASK, MOVE_WIDE_32) &&
                (encoding & 31) == X2 && ((encoding >>> 21) & 3) == 0;
    }

    private boolean isMove(int encoding, int destination, int source, boolean wide) {
        return isMoveRegister(encoding) && (encoding & 31) == destination &&
                sourceRegister(encoding) == source && is64Bit(encoding) == wide;
    }

    private boolean isMoveRegister(int encoding) {
        return matches(encoding, MOVE_REGISTER_MASK, MOVE_REGISTER);
    }

    private int sourceRegister(int encoding) {
        return (encoding >>> 16) & 31;
    }

    private boolean is64Bit(int encoding) {
        return (encoding & 0x8000_0000) != 0;
    }

    private boolean isCalleeSaved(int register) {
        return register >= FIRST_CALLEE_SAVED && register <= LAST_CALLEE_SAVED;
    }

    private boolean matches(int encoding, int mask, int expected) {
        return (encoding & mask) == expected;
    }
}
