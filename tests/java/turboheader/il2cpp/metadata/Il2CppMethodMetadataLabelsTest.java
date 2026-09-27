package turboheader.il2cpp.metadata;

public final class Il2CppMethodMetadataLabelsTest {
    public static void main(String[] args) {
        String managed = "Method$List<Fixture.SampleItem>.get_Item()";
        check(Il2CppMethodMetadataLabels.target(0x01234567, managed).equals(
                "Method_Method$List_Fixture_SampleItem_get_Item_01234567"),
                "target label");
        check(Il2CppMethodMetadataLabels.pointer(0x07654321, managed).equals(
                "PTR_Method_Method$List_Fixture_SampleItem_get_Item_07654321"),
                "pointer label");
        check(Il2CppMethodMetadataLabels.comment(managed).equals(
                "IL2CPP method metadata: " + managed), "comment");
        check(Il2CppMethodMetadataLabels.target(1, "<>").contains("unnamed_00000001"),
                "empty sanitized name");
        System.out.println("method metadata label tests passed");
    }

    private static void check(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }
}
