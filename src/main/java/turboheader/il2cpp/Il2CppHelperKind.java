package turboheader.il2cpp;

/** IL2CPP runtime helpers whose identity can be established without address guesses. */
public enum Il2CppHelperKind {
    METADATA_INIT("il2cpp_meta_init"),
    OBJECT_NEW("il2cpp_object_new"),
    ARRAY_NEW("il2cpp_array_new"),
    CLASS_INIT("il2cpp_class_init"),
    GC_WRITE_BARRIER("il2cpp_gc_wbarrier"),
    THROW("il2cpp_throw");

    private final String stem;

    Il2CppHelperKind(String stem) {
        this.stem = stem;
    }

    String stem() {
        return stem;
    }
}
