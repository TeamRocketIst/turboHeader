package turboheader.il2cpp.analysis;

import java.util.Map;
import java.util.OptionalInt;
import java.util.Set;
import turboheader.il2cpp.analysis.architecture.ControlFlowDecoder;
import turboheader.il2cpp.analysis.architecture.aarch64.Aarch64Architecture;

public final class NoreturnProofEngineTest {
    public static void main(String[] args) {
        decoderClassifiesNamedControlFlowKinds();
        proofRequiresEveryReachablePathToDeadEnd();
        proofUsesDecoderInstructionSize();
        System.out.println("noreturn proof-engine tests passed");
    }

    private static void decoderClassifiesNamedControlFlowKinds() {
        var decoder = Aarch64Architecture.controlFlowDecoder();
        require(decoder.decode(0x1000, branch(0x1400_0000, 0x1000, 0x2000)).kind() ==
                ControlFlowDecoder.Kind.DIRECT_JUMP, "direct jump");
        require(decoder.decode(0x1000, branch(0x9400_0000, 0x1000, 0x2000)).kind() ==
                ControlFlowDecoder.Kind.DIRECT_CALL, "direct call");
        require(decoder.decode(0x1000, 0xd63f_0000).kind() ==
                ControlFlowDecoder.Kind.INDIRECT_CALL, "indirect call");
        require(decoder.decode(0x1000, 0xd65f_03c0).kind() ==
                ControlFlowDecoder.Kind.RETURN, "return");
        require(decoder.decode(0x1000, 0xd61f_0000).kind() ==
                ControlFlowDecoder.Kind.INDIRECT_JUMP, "indirect jump");
        require(decoder.decode(0x1000, 0x5400_0000).kind() ==
                ControlFlowDecoder.Kind.CONDITIONAL_BRANCH, "conditional branch");
    }

    private static void proofRequiresEveryReachablePathToDeadEnd() {
        Map<Long, Integer> words = Map.of(
                0x1000L, branch(0x9400_0000, 0x1000, 0x2000),
                0x1004L, 0xd65f_03c0,
                0x1100L, branch(0x9400_0000, 0x1100, 0x4000),
                0x1104L, 0xd65f_03c0,
                0x2000L, branch(0x1400_0000, 0x2000, 0x8000),
                0x4000L, 0xd65f_03c0);
        NoreturnProofEngine.WordSource source = address -> {
            Integer word = words.get(address);
            return word == null ? OptionalInt.empty() : OptionalInt.of(word);
        };
        var result = new NoreturnProofEngine(
                source, Set.of(0x1000L, 0x1100L), Set.of(0x8000L),
                Aarch64Architecture.controlFlowDecoder()).discover();
        require(result.proven().contains(0x2000L), "noreturn helper should be proven");
        require(result.proven().contains(0x8000L), "terminal leaf should be retained");
        require(!result.proven().contains(0x4000L), "returning helper must fail safe");
        require(result.provenHelpers().equals(Set.of(0x2000L)),
                "only transitively proven helpers should be classified for renaming");
    }

    private static void proofUsesDecoderInstructionSize() {
        Map<Long, Integer> words = Map.of(
                0x1000L, 1,
                0x1002L, 2,
                0x1004L, 4,
                0x2000L, 3);
        NoreturnProofEngine.WordSource source = address -> {
            Integer word = words.get(address);
            return word == null ? OptionalInt.empty() : OptionalInt.of(word);
        };
        var result = new NoreturnProofEngine(
                source, Set.of(0x1000L), Set.of(0x8000L), new TwoByteDecoder()).discover();
        require(result.provenHelpers().contains(0x2000L),
                "proof engine must use the decoder instruction size");
    }

    private static final class TwoByteDecoder implements ControlFlowDecoder {
        @Override
        public int instructionSize() {
            return 2;
        }

        @Override
        public DecodedInstruction decode(long address, int encoding) {
            return switch (encoding) {
                case 2 -> new DecodedInstruction(Kind.DIRECT_CALL, 0x2000L);
                case 3 -> new DecodedInstruction(Kind.DIRECT_JUMP, 0x8000L);
                case 4 -> DecodedInstruction.simple(Kind.RETURN);
                default -> DecodedInstruction.simple(Kind.OTHER);
            };
        }

        @Override
        public boolean isAbiTailTeardown(int encoding) {
            return false;
        }
    }

    private static int branch(int opcode, long address, long target) {
        long displacement = (target - address) >> 2;
        return opcode | (int) (displacement & 0x03ff_ffffL);
    }

    private static void require(boolean value, String message) {
        if (!value) {
            throw new AssertionError(message);
        }
    }
}
