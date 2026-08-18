package turboheader.il2cpp;

public final class MethodAssemblyIdentityTest {
    public static void main(String[] args) {
        String comment = MethodAssemblyIdentity.write("user note", "Assembly-CSharp");
        check(comment.startsWith("user note\n"), "preserves user comment");
        check("Assembly-CSharp".equals(MethodAssemblyIdentity.read(comment)), "round trip");

        String updated = MethodAssemblyIdentity.write(comment, "Gameplay.Runtime");
        check(!updated.contains("Assembly-CSharp"), "replaces stale identity");
        check("Gameplay.Runtime".equals(MethodAssemblyIdentity.read(updated)), "updated identity");
        System.out.println("method assembly identity tests passed");
    }

    private static void check(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }
}
