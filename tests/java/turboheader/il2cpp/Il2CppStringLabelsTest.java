package turboheader.il2cpp;

public final class Il2CppStringLabelsTest {
    public static void main(String[] args) {
        check(Il2CppStringLabels.label(0x2ef11f8, "Attempt ")
                .equals("PTR_str_Attempt\\x20_02ef11f8"), "readable label");
        check(Il2CppStringLabels.label(1, "\n\té").equals(
                "PTR_str_\\x0a\\x09\\xe9_00000001"), "escaped label");
        check(Il2CppStringLabels.label(2, "a  / b---c").equals(
                "PTR_str_a\\x20\\x20/\\x20b---c_00000002"), "literal label");
        check(Il2CppStringLabels.label(3, "same").endsWith("_00000003"),
                "address disambiguation");
        check(Il2CppStringLabels.label(4, "same").endsWith("_00000004"),
                "duplicate value disambiguation");

        String comment = Il2CppStringLabels.comment("line\n\t\"\\é\u0001");
        check(comment.equals("IL2CPP string: \"line\\n\\t\\\"\\\\é\\u0001\""),
                "escaped comment");
        check(!comment.contains("\n"), "single-line comment");

        String huge = "x".repeat(5000);
        String bounded = Il2CppStringLabels.comment(huge);
        check(bounded.length() == Il2CppStringLabels.MAX_COMMENT_LENGTH, "bounded comment");
        check(bounded.endsWith("[truncated; code points=5000]"), "truncation marker");

        String hugeLabel = Il2CppStringLabels.label(5, "é".repeat(1000));
        check(hugeLabel.length() == Il2CppStringLabels.MAX_LABEL_LENGTH,
                "bounded label");
        check(hugeLabel.contains("..._00000005"), "label truncation marker");
        check(!hugeLabel.contains("\\xe..."), "escape token was split");
        System.out.println("IL2CPP string label tests passed");
    }

    private static void check(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }
}
