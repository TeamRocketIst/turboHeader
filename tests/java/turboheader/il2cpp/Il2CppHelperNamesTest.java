package turboheader.il2cpp;

public final class Il2CppHelperNamesTest {
    public static void main(String[] args) {
        require(Il2CppHelperNames.mappedName(Il2CppHelperKind.METADATA_INIT, 0x15ba93cL)
                .equals("il2cpp_meta_init_015ba93c"), "metadata helper name");
        require(Il2CppHelperNames.mappedName(Il2CppHelperKind.OBJECT_NEW, 0x15ed724L)
                .equals("il2cpp_object_new_015ed724"), "object helper name");
        require(Il2CppHelperNames.mappedName(Il2CppHelperKind.GC_WRITE_BARRIER, 0x1624d84L)
                .equals("il2cpp_gc_wbarrier_01624d84"), "write-barrier helper name");
        System.out.println("IL2CPP helper-name tests passed");
    }

    private static void require(boolean value, String message) {
        if (!value) {
            throw new AssertionError(message);
        }
    }
}
