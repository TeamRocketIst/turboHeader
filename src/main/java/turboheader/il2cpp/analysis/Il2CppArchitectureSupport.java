package turboheader.il2cpp.analysis;

import java.util.Objects;
import java.util.Optional;

import ghidra.program.model.listing.Program;

final class Il2CppArchitectureSupport {
    private Il2CppArchitectureSupport() {
    }

    static Support inspect(Program program) {
        Objects.requireNonNull(program, "program");
        String processor = program.getLanguage().getProcessor().toString();
        boolean aarch64 = processor.equalsIgnoreCase("AARCH64");
        ControlFlowDecoder decoder = aarch64 ? new Aarch64ControlFlowDecoder() : null;
        ArchitectureHelperProof helperProof = aarch64
                ? new Aarch64InterfaceDispatchProof() : null;
        return new Support(processor, Optional.ofNullable(decoder),
                Optional.ofNullable(helperProof));
    }

    record Support(String processor, Optional<ControlFlowDecoder> controlFlowDecoder,
            Optional<ArchitectureHelperProof> helperProof) {
        Support {
            Objects.requireNonNull(processor, "processor");
            Objects.requireNonNull(controlFlowDecoder, "controlFlowDecoder");
            Objects.requireNonNull(helperProof, "helperProof");
        }

        boolean supportsLocalNoreturn() {
            return controlFlowDecoder.isPresent();
        }

        ControlFlowDecoder requireControlFlowDecoder() {
            return controlFlowDecoder.orElseThrow(() -> new IllegalStateException(
                    "TurboHeader noreturn discovery does not support " + processor));
        }
    }
}
