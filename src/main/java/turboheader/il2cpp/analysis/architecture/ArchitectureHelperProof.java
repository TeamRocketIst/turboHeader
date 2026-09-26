package turboheader.il2cpp.analysis.architecture;

import java.util.List;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.Set;
import turboheader.il2cpp.analysis.helpers.Il2CppHelperKind;

public interface ArchitectureHelperProof {
    Result analyze(Input input);

    interface ExecutableWords {
        OptionalInt read(long address);

        boolean isExecutable(long address);
    }

    record Input(List<ManagedMethod> methods, Set<Long> managedMethods,
            ExecutableWords words) {
        public Input {
            methods = List.copyOf(methods);
            managedMethods = Set.copyOf(managedMethods);
            Objects.requireNonNull(words, "words");
        }
    }

    record ManagedMethod(long entry, long endExclusive, List<InstructionWord> instructions) {
        public ManagedMethod {
            if (Long.compareUnsigned(entry, endExclusive) >= 0) {
                throw new IllegalArgumentException("managed method range must not be empty");
            }
            instructions = List.copyOf(instructions);
        }

        public boolean contains(long address) {
            return Long.compareUnsigned(address, entry) >= 0 &&
                    Long.compareUnsigned(address, endExclusive) < 0;
        }
    }

    record InstructionWord(long address, int encoding) {
    }

    record Evidence(Il2CppHelperKind kind, long helperAddress, long witnessAddress,
            long layoutOffset) {
    }

    record Result(List<Evidence> evidence, int callsiteCandidates,
            int helperCandidates, int rejectedHelpers) {
        public Result {
            evidence = List.copyOf(evidence);
            if (callsiteCandidates < 0 || helperCandidates < 0 || rejectedHelpers < 0) {
                throw new IllegalArgumentException("proof counters must not be negative");
            }
        }
    }
}
