package turboheader.il2cpp.metadata;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class RuntimeLayoutInfoTest {
    private static final String TABLES = "\"ScriptMethod\":[],\"ScriptString\":[{\"Address\":16,\"Value\":\"Sample\"}]," +
            "\"ScriptInterfaceDispatch\":[],\"ScriptDelegateSignature\":[],\"ScriptSharedGenericCall\":[],\"ScriptReferenceGenericCall\":[]";

    public static void main(String[] args) throws Exception {
        Path path = Files.createTempFile("runtime-layout-test", ".json");
        try {
            for (String status : new String[] { "verified", "familyFallback", "legacyCompatibility", "opaque" }) {
                boolean trusted = status.equals("verified");
                String marker = marker(status, trusted);
                for (boolean first : new boolean[] { false, true }) {
                    Files.writeString(path, first ? "{\"RuntimeLayout\":" + marker + "," + TABLES + "}"
                            : "{" + TABLES + ",\"RuntimeLayout\":" + marker + "}");
                    var data = ScriptMethodReader.readAll(path);
                    check(data.runtimeLayout().orElseThrow().status().equals(status), "status lost");
                    check(data.strings().size() == 1, "ordinary strings lost");
                    check(data.interfaceDispatch().isPresent() == trusted, "interface policy");
                    check(data.delegateSignatures().isPresent() == trusted, "delegate policy");
                    check(data.sharedGenericCalls().isPresent() == trusted, "shared-generic policy");
                    check(data.referenceGenericCalls().isPresent() == trusted, "reference-generic policy");
                }
                Files.writeString(path, "{\"runtimeLayout\":" + marker + ",\"types\":{}}");
                check(RuntimeLayoutInfo.readOffsets(path).orElseThrow().runtimeFieldsVerified() == trusted, "offset policy");
            }
            Files.writeString(path, "{" + TABLES + "}");
            check(ScriptMethodReader.readAll(path).interfaceDispatch().isPresent(), "legacy catalogs lost");
            Files.writeString(path, "{\"types\":{}}");
            check(RuntimeLayoutInfo.readOffsets(path).isEmpty(), "legacy offsets changed");

            for (String invalid : new String[] { "null", "[]", "{}",
                    marker("opaque", true), marker("verified", false), marker("unknown", false),
                    marker("verified", true).replace("\"legacy\"", "\"unknown\""),
                    marker("verified", true).replace("\"pointerSize\":8", "\"pointerSize\":4"),
                    marker("verified", true).replace("\"pointerSize\":8", "\"pointerSize\":\"8\""),
                    marker("verified", true).replace("\"pointerSize\":8", "\"pointerSize\":8.0"),
                    marker("verified", true).replace("true", "\"true\""),
                    marker("opaque", false).replace("\"status\":", "\"status\":\"opaque\",\"status\":") }) {
                Files.writeString(path, "{" + TABLES + ",\"RuntimeLayout\":" + invalid + "}");
                expectFailure(path, false);
                Files.writeString(path, "{\"runtimeLayout\":" + invalid + ",\"types\":{}}");
                expectFailure(path, true);
            }
            String marker = marker("verified", true);
            Files.writeString(path, "{" + TABLES + ",\"RuntimeLayout\":" + marker + ",\"RuntimeLayout\":" + marker + "}");
            expectFailure(path, false);
            Files.writeString(path, "{\"runtimeLayout\":" + marker + ",\"types\":{},\"runtimeLayout\":" + marker + "}");
            expectFailure(path, true);
            Files.writeString(path, "{\"runtimeLayout\":" + marker + "} {}");
            expectFailure(path, true);
        }
        finally {
            Files.deleteIfExists(path);
        }
        System.out.println("RuntimeLayoutInfoTest passed");
    }

    private static String marker(String status, boolean verified) {
        return "{\"status\":\"" + status + "\",\"pointerSize\":8,\"profile\":\"legacy\",\"runtimeFieldsVerified\":" + verified + "}";
    }

    private static void expectFailure(Path path, boolean offsets) throws Exception {
        try {
            if (offsets) RuntimeLayoutInfo.readOffsets(path);
            else ScriptMethodReader.readAll(path);
            throw new AssertionError("invalid runtime confidence accepted");
        }
        catch (IOException expected) {
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
