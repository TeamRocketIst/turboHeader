// @category Test

import java.io.IOException;
import java.util.Optional;

import ghidra.app.script.GhidraScript;
import turboheader.il2cpp.metadata.Il2CppDelegateSignatureStore;
import turboheader.il2cpp.metadata.Il2CppInterfaceDispatchStore;
import turboheader.il2cpp.metadata.Il2CppReferenceGenericCallStore;
import turboheader.il2cpp.metadata.Il2CppSharedGenericCallStore;
import turboheader.il2cpp.metadata.RuntimeLayoutInfo;
import turboheader.il2cpp.metadata.RuntimeLayoutStore;

public class VerifyTurboHeaderRuntimeLayoutStore extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var verified = new RuntimeLayoutInfo("verified", 8, true, "legacy");
        var fallback = new RuntimeLayoutInfo("familyFallback", 8, false, "legacy");
        boolean write = getScriptArgs().length == 1 && getScriptArgs()[0].equals("write");
        if (write) {
            RuntimeLayoutStore.replace(currentProgram, Optional.empty());
            require(RuntimeLayoutStore.allowsProofs(currentProgram), "legacy project changed");
            RuntimeLayoutStore.replace(currentProgram, Optional.of(verified));
            require(RuntimeLayoutStore.allowsProofs(currentProgram), "verified layout blocked");
            try {
                RuntimeLayoutStore.merge(currentProgram, Optional.of(fallback));
                throw new AssertionError("conflicting confidence accepted");
            }
            catch (IOException expected) {
                require(RuntimeLayoutStore.allowsProofs(currentProgram), "failed merge changed confidence");
            }
            var other = new RuntimeLayoutInfo("verified", 8, true, "interface-data");
            try {
                RuntimeLayoutStore.merge(currentProgram, Optional.of(other));
                throw new AssertionError("conflicting profile accepted");
            }
            catch (IOException expected) {
            }
            var options = currentProgram.getOptions("TurboHeader IL2CPP");
            options.removeOption("Runtime Layout Pointer Size");
            expectInvalidStore();
            RuntimeLayoutStore.replace(currentProgram, Optional.of(verified));
            options.removeOption("Runtime Layout Status");
            options.setInt("Runtime Layout Status", 1);
            expectInvalidStore();
            options.removeOption("Runtime Layout Status");
            RuntimeLayoutStore.replace(currentProgram, Optional.of(fallback));
            blocked();
            require(!RuntimeLayoutStore.merge(currentProgram, Optional.empty()), "absent marker changed confidence");
            blocked();
            println("TurboHeader runtime layout confidence stored");
        }
        else {
            blocked();
            RuntimeLayoutStore.replace(currentProgram, Optional.of(verified));
            require(RuntimeLayoutStore.allowsProofs(currentProgram), "verified restore failed");
            require(Il2CppInterfaceDispatchStore.read(currentProgram).isPresent(), "catalog was deleted instead of gated");
            println("TurboHeader runtime layout confidence survived project reopen");
        }
    }

    private void expectInvalidStore() throws Exception {
        try {
            RuntimeLayoutStore.allowsProofs(currentProgram);
            throw new AssertionError("invalid stored confidence accepted");
        }
        catch (IOException expected) {
        }
    }

    private void blocked() throws Exception {
        require(!RuntimeLayoutStore.allowsProofs(currentProgram), "unverified layout was trusted");
        require(Il2CppInterfaceDispatchStore.read(currentProgram).isEmpty(), "interface facts escaped guard");
        require(Il2CppDelegateSignatureStore.read(currentProgram).isEmpty(), "delegate facts escaped guard");
        require(Il2CppSharedGenericCallStore.read(currentProgram).isEmpty(), "shared-generic facts escaped guard");
        require(Il2CppReferenceGenericCallStore.read(currentProgram).isEmpty(), "reference-generic facts escaped guard");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
