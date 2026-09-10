package turboheader.il2cpp;

import java.nio.file.Path;

/** Imports an IL2CPP header into a Ghidra program. */
public interface Il2CppTypeImportStrategy {
    void importTypes(Path header, Path offsets, int pointerSize,
            Il2CppLayoutPolicy layoutPolicy) throws Exception;
}
