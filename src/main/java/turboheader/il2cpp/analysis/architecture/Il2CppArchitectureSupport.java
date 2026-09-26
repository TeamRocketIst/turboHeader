package turboheader.il2cpp.analysis.architecture;

import java.util.Objects;
import java.util.Optional;

import ghidra.program.model.listing.Program;
import turboheader.il2cpp.analysis.architecture.aarch64.Aarch64Architecture;

public final class Il2CppArchitectureSupport {
    private Il2CppArchitectureSupport() {
    }

    public static Support inspect(Program program) {
        Objects.requireNonNull(program, "program");
        String processor = program.getLanguage().getProcessor().toString();
        boolean aarch64 = processor.equalsIgnoreCase("AARCH64");
        ControlFlowDecoder decoder = aarch64
                ? Aarch64Architecture.controlFlowDecoder() : null;
        ArchitectureHelperProof helperProof = aarch64
                ? Aarch64Architecture.helperProof() : null;
        return new Support(processor, Optional.ofNullable(decoder),
                Optional.ofNullable(helperProof));
    }

    public record Support(String processor, Optional<ControlFlowDecoder> controlFlowDecoder,
            Optional<ArchitectureHelperProof> helperProof) {
        public Support {
            Objects.requireNonNull(processor, "processor");
            Objects.requireNonNull(controlFlowDecoder, "controlFlowDecoder");
            Objects.requireNonNull(helperProof, "helperProof");
        }

        public boolean supportsLocalNoreturn() {
            return controlFlowDecoder.isPresent();
        }

        public ControlFlowDecoder requireControlFlowDecoder() {
            return controlFlowDecoder.orElseThrow(() -> new IllegalStateException(
                    "TurboHeader noreturn discovery does not support " + processor));
        }
    }
}
