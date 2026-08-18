package turboheader.il2cpp;

import java.util.Map;
import java.util.OptionalInt;
import java.util.Set;

public final class NoreturnProofEngineTest {
    public static void main(String[] args) {
        decoderClassifiesNamedControlFlowKinds();
        proofRequiresEveryReachablePathToDeadEnd();
        System.out.println("noreturn proof-engine tests passed");
    }

    private static void decoderClassifiesNamedControlFlowKinds() {
        var decoder = new Aarch64ControlFlowDecoder();
        require(decoder.decode(0x1000, branch(0x1400_0000, 0x1000, 0x2000)).kind() ==
                Aarch64ControlFlowDecoder.Kind.DIRECT_JUMP, "direct jump");
        require(decoder.decode(0x1000, branch(0x9400_0000, 0x1000, 0x2000)).kind() ==
                Aarch64ControlFlowDecoder.Kind.DIRECT_CALL, "direct call");
        require(decoder.decode(0x1000, 0xd63f_0000).kind() ==
                Aarch64ControlFlowDecoder.Kind.INDIRECT_CALL, "indirect call");
        require(decoder.decode(0x1000, 0xd65f_03c0).kind() ==
                Aarch64ControlFlowDecoder.Kind.RETURN, "return");
        require(decoder.decode(0x1000, 0xd61f_0000).kind() ==
                Aarch64ControlFlowDecoder.Kind.INDIRECT_JUMP, "indirect jump");
        require(decoder.decode(0x1000, 0x5400_0000).kind() ==
                Aarch64ControlFlowDecoder.Kind.CONDITIONAL_BRANCH, "conditional branch");
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
                source, Set.of(0x1000L, 0x1100L), Set.of(0x8000L)).discover();
        require(result.proven().contains(0x2000L), "noreturn helper should be proven");
        require(result.proven().contains(0x8000L), "terminal leaf should be retained");
        require(!result.proven().contains(0x4000L), "returning helper must fail safe");
        require(result.provenHelpers().equals(Set.of(0x2000L)),
                "only transitively proven helpers should be classified for renaming");
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
