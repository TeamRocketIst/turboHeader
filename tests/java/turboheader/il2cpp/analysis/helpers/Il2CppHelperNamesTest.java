package turboheader.il2cpp.analysis.helpers;

public final class Il2CppHelperNamesTest {
    public static void main(String[] args) {
        require(Il2CppHelperNames.mappedName(Il2CppHelperKind.METADATA_INIT, 0x01111111L)
                .equals("il2cpp_meta_init_01111111"), "metadata helper name");
        require(Il2CppHelperNames.mappedName(Il2CppHelperKind.OBJECT_NEW, 0x02222222L)
                .equals("il2cpp_object_new_02222222"), "object helper name");
        require(Il2CppHelperNames.mappedName(Il2CppHelperKind.GC_WRITE_BARRIER, 0x03333333L)
                .equals("il2cpp_gc_wbarrier_03333333"), "write-barrier helper name");
        require(Il2CppHelperNames.mappedName(
                Il2CppHelperKind.INTERFACE_INVOKE_LOOKUP, 0x5000L).equals(
                "il2cpp_GetInterfaceInvokeDataFromVTableSlowPath_00005000"),
                "interface lookup helper name");
        System.out.println("IL2CPP helper-name tests passed");
    }

    private static void require(boolean value, String message) {
        if (!value) {
            throw new AssertionError(message);
        }
    }
}
