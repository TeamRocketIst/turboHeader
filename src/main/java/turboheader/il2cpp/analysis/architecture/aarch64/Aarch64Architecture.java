package turboheader.il2cpp.analysis.architecture.aarch64;

import turboheader.il2cpp.analysis.architecture.ArchitectureHelperProof;
import turboheader.il2cpp.analysis.architecture.ControlFlowDecoder;

public final class Aarch64Architecture {
    private Aarch64Architecture() {
    }

    public static ControlFlowDecoder controlFlowDecoder() {
        return new Aarch64ControlFlowDecoder();
    }

    public static ArchitectureHelperProof helperProof() {
        return new Aarch64InterfaceDispatchProof();
    }
}
