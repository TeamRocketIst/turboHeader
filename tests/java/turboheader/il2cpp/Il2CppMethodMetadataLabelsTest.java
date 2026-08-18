package turboheader.il2cpp;

public final class Il2CppMethodMetadataLabelsTest {
    public static void main(String[] args) {
        String managed = "Method$List<JavelinThrowGame.DustParticle>.get_Item()";
        check(Il2CppMethodMetadataLabels.target(0x2eddc30, managed).equals(
                "Method_Method$List_JavelinThrowGame_DustParticle_get_Item_02eddc30"),
                "target label");
        check(Il2CppMethodMetadataLabels.pointer(0x2e59058, managed).equals(
                "PTR_Method_Method$List_JavelinThrowGame_DustParticle_get_Item_02e59058"),
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
