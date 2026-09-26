package turboheader.il2cpp.analysis.architecture.aarch64;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import java.util.Set;
import turboheader.il2cpp.analysis.helpers.Il2CppHelperKind;
import turboheader.il2cpp.analysis.architecture.ArchitectureHelperProof;

public final class Aarch64InterfaceDispatchProofTest {
    private static final long HELPER = 0x5000;
    private static final long METHOD = 0x7000;
    private static final long NATIVE_CALL = 0x9000;
    private static final long VTABLE_OFFSET = 0x138;

    public static void main(String[] args) {
        acceptsIndependentCallsiteAndHelperProofs();
        rejectsInexactCallsiteShapes();
        rejectsManagedAndInvalidHelpers();
        rejectsConflictingLayoutEvidence();
        System.out.println("AArch64 interface-dispatch proof tests passed");
    }

    private static void acceptsIndependentCallsiteAndHelperProofs() {
        Fixture fixture = fixture(METHOD, VTABLE_OFFSET);
        ArchitectureHelperProof.Result result = analyze(
                List.of(fixture.method()), Set.of(METHOD), fixture.memory());
        require(result.evidence().equals(List.of(new ArchitectureHelperProof.Evidence(
                Il2CppHelperKind.INTERFACE_INVOKE_LOOKUP, HELPER, METHOD + 8,
                VTABLE_OFFSET))), "valid interface dispatch should be proven");
        require(result.callsiteCandidates() == 1 && result.helperCandidates() == 1 &&
                result.rejectedHelpers() == 0, "valid proof counters");
    }

    private static void rejectsInexactCallsiteShapes() {
        Fixture fixture = fixture(METHOD, VTABLE_OFFSET);
        requireRejected(fixture, replace(fixture.method(), 1, moveImmediate32(3, 0)),
                "slot register");
        requireRejected(fixture, replace(fixture.method(), 5,
                addShifted(8, 8, 9, 3)), "invoke-data scale");
        requireRejected(fixture, replace(fixture.method(), 9, indirectCall(7)),
                "dispatch register");

        var instructions = new ArrayList<>(fixture.method().instructions());
        var original = instructions.get(6);
        instructions.set(6, new ArchitectureHelperProof.InstructionWord(
                original.address() + 4, original.encoding()));
        var noncontiguous = new ArchitectureHelperProof.ManagedMethod(
                METHOD, METHOD + 0x100, instructions);
        requireRejected(fixture, noncontiguous, "noncontiguous window");
    }

    private static void rejectsManagedAndInvalidHelpers() {
        Fixture fixture = fixture(METHOD, VTABLE_OFFSET);
        require(analyze(List.of(fixture.method()), Set.of(METHOD, HELPER), fixture.memory())
                .evidence().isEmpty(),
                "managed helper target must be rejected");

        SyntheticMemory invalid = fixture.memory().copy();
        invalid.put(HELPER + 8, nop());
        require(analyze(List.of(fixture.method()), Set.of(METHOD), invalid).evidence().isEmpty(),
                "helper without three preserved arguments must be rejected");

        SyntheticMemory misleading = fixture.memory().copy();
        misleading.put(HELPER + 0x14, conditionalBranch(HELPER + 0x14, HELPER + 0x90));
        misleading.put(HELPER + 0x1c, conditionalBranch(HELPER + 0x1c, HELPER + 0x80));
        require(analyze(List.of(fixture.method()), Set.of(METHOD), misleading)
                .evidence().isEmpty(),
                "later branch must not replace an invalid first conditional split");
    }

    private static void rejectsConflictingLayoutEvidence() {
        Fixture first = fixture(METHOD, VTABLE_OFFSET);
        Fixture second = fixture(0x8000, 0x140);
        var result = analyze(List.of(first.method(), second.method()), Set.of(METHOD, 0x8000L),
                first.memory());
        require(result.evidence().isEmpty() && result.rejectedHelpers() == 1,
                "conflicting vtable offsets must be rejected");
    }

    private static void requireRejected(Fixture fixture,
            ArchitectureHelperProof.ManagedMethod method, String reason) {
        require(analyze(List.of(method), Set.of(METHOD), fixture.memory()).evidence().isEmpty(),
                reason + " must be rejected");
    }

    private static ArchitectureHelperProof.Result analyze(
            List<ArchitectureHelperProof.ManagedMethod> methods, Set<Long> managed,
            SyntheticMemory memory) {
        var input = new ArchitectureHelperProof.Input(methods, managed, memory);
        return new Aarch64InterfaceDispatchProof().analyze(input);
    }

    private static Fixture fixture(long methodAddress, long vtableOffset) {
        SyntheticMemory memory = helperMemory();
        List<ArchitectureHelperProof.InstructionWord> instructions = List.of(
                word(methodAddress, moveRegister(0, 19, true)),
                word(methodAddress + 4, moveImmediate32(2, 0)),
                word(methodAddress + 8, branch(0x9400_0000, methodAddress + 8, HELPER)),
                word(methodAddress + 12,
                        branch(0x1400_0000, methodAddress + 12, methodAddress + 0x1c)),
                word(methodAddress + 0x10, loadSignedWord(9, 10)),
                word(methodAddress + 0x14, addShifted(8, 8, 9, 4)),
                word(methodAddress + 0x18, addImmediate(0, 8, vtableOffset)),
                word(methodAddress + 0x1c, loadPair(8, 1, 0)),
                word(methodAddress + 0x20, moveRegister(0, 19, true)),
                word(methodAddress + 0x24, indirectCall(8)));
        return new Fixture(new ArchitectureHelperProof.ManagedMethod(
                methodAddress, methodAddress + 0x100, instructions), memory);
    }

    private static SyntheticMemory helperMemory() {
        SyntheticMemory memory = new SyntheticMemory();
        int[] words = {
                0xa9bd_5ffe,
                moveRegister(22, 0, true),
                moveRegister(20, 1, true),
                moveRegister(19, 2, false),
                branch(0x9400_0000, HELPER + 0x10, NATIVE_CALL),
                conditionalBranch(HELPER + 0x14, HELPER + 0x80),
                nop(), nop(), nop(), nop(), nop(), nop()
        };
        for (int index = 0; index < words.length; index++) {
            memory.put(HELPER + (long) index * 4, words[index]);
        }
        memory.executable(NATIVE_CALL);
        memory.executable(HELPER + 0x80);
        return memory;
    }

    private static ArchitectureHelperProof.ManagedMethod replace(
            ArchitectureHelperProof.ManagedMethod method, int index, int encoding) {
        var instructions = new ArrayList<>(method.instructions());
        var original = instructions.get(index);
        instructions.set(index, new ArchitectureHelperProof.InstructionWord(
                original.address(), encoding));
        return new ArchitectureHelperProof.ManagedMethod(
                method.entry(), method.endExclusive(), instructions);
    }

    private static ArchitectureHelperProof.InstructionWord word(long address, int encoding) {
        return new ArchitectureHelperProof.InstructionWord(address, encoding);
    }

    private static int moveRegister(int destination, int source, boolean wide) {
        int opcode = wide ? 0xaa00_03e0 : 0x2a00_03e0;
        return opcode | source << 16 | destination;
    }

    private static int moveImmediate32(int destination, int value) {
        return 0x5280_0000 | value << 5 | destination;
    }

    private static int loadSignedWord(int destination, int base) {
        return 0xb980_0000 | base << 5 | destination;
    }

    private static int addShifted(int destination, int left, int right, int shift) {
        return 0x8b00_0000 | right << 16 | shift << 10 | left << 5 | destination;
    }

    private static int addImmediate(int destination, int source, long value) {
        return 0x9100_0000 | (int) value << 10 | source << 5 | destination;
    }

    private static int loadPair(int first, int second, int base) {
        return 0xa940_0000 | second << 10 | base << 5 | first;
    }

    private static int indirectCall(int register) {
        return 0xd63f_0000 | register << 5;
    }

    private static int conditionalBranch(long address, long target) {
        long displacement = (target - address) >> 2;
        return 0x5400_0000 | (int) (displacement & 0x7_ffffL) << 5;
    }

    private static int branch(int opcode, long address, long target) {
        long displacement = (target - address) >> 2;
        return opcode | (int) (displacement & 0x03ff_ffffL);
    }

    private static int nop() {
        return 0xd503_201f;
    }

    private static void require(boolean value, String message) {
        if (!value) {
            throw new AssertionError(message);
        }
    }

    private record Fixture(ArchitectureHelperProof.ManagedMethod method,
            SyntheticMemory memory) {
    }

    private static final class SyntheticMemory implements ArchitectureHelperProof.ExecutableWords {
        private final Map<Long, Integer> words = new HashMap<>();
        private final Set<Long> executable = new HashSet<>();

        void put(long address, int encoding) {
            words.put(address, encoding);
            executable.add(address);
        }

        void executable(long address) {
            executable.add(address);
        }

        SyntheticMemory copy() {
            SyntheticMemory result = new SyntheticMemory();
            result.words.putAll(words);
            result.executable.addAll(executable);
            return result;
        }

        @Override
        public OptionalInt read(long address) {
            Integer encoding = words.get(address);
            return encoding == null ? OptionalInt.empty() : OptionalInt.of(encoding);
        }

        @Override
        public boolean isExecutable(long address) {
            return executable.contains(address);
        }
    }
}
