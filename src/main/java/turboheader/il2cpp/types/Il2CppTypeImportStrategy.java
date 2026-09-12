package turboheader.il2cpp.types;

import java.nio.file.Path;

import turboheader.il2cpp.Il2CppLayoutPolicy;

/** Imports an IL2CPP header into a Ghidra program. */
public interface Il2CppTypeImportStrategy {
    void importTypes(Path header, Path offsets, int pointerSize,
            Il2CppLayoutPolicy layoutPolicy) throws Exception;
}
