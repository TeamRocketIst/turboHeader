package turboheader.il2cpp.metadata;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public final class Il2CppReferenceGenericCallCatalogTest {
    private static final String SIGNATURE =
            "Sample_Item_o* reference_generic_call (Sample_Box_o* __this, int32_t arg1, const MethodInfo* method);";
    private static int checks;

    public static void main(String[] args) throws Exception {
        testCatalog();
        testSignature();
        testCodec();
        testReader();
        testBounds();
        System.out.println("reference generic call catalogue tests passed: " + checks + " checks");
    }

    private static void testCatalog() throws Exception {
        var first = row(0x100, 7, 0x300, SIGNATURE);
        var second = row(0x120, 8, 0x300, SIGNATURE);
        var source = List.of(second, first, first);
        var catalog = Il2CppReferenceGenericCallCatalog.restored(source);
        check(catalog.entries().equals(List.of(first, second)), "sorted distinct entries");
        check(source.getFirst().equals(second), "input order unchanged");
        check(catalog.forMethodAddress(0x300).size() == 2, "shared target lookup");
        check(catalog.forMethodAddress(0x400).isEmpty(), "missing target");
        check(catalog.forMethodInfoAddress(0x100).orElseThrow().methodSpecIndex() == 7, "slot lookup");
        check(catalog.forMethodInfoAddress(0x200).isEmpty(), "missing slot");
        expectImmutable(() -> catalog.entries().clear());
        expectImmutable(() -> catalog.forMethodAddress(0x300).clear());
        var absent = new ScriptMethodReader.ScriptData(List.of(), List.of(), List.of(), List.of());
        check(Il2CppReferenceGenericCallCatalog.fromScript(absent).isEmpty(), "absent table");
        check(Il2CppReferenceGenericCallCatalog.restored(List.of()).entries().isEmpty(), "empty table");
        for (var conflict : List.of(row(0x100, 8, 0x300, SIGNATURE), row(0x100, 7, 0x400, SIGNATURE),
                row(0x100, 7, 0x300, SIGNATURE.replace("Sample_Item", "Sample_Other")))) {
            fails(() -> Il2CppReferenceGenericCallCatalog.restored(List.of(first, conflict)));
            fails(() -> Il2CppReferenceGenericCallCatalog.restored(List.of(conflict, first)));
        }
        for (var invalid : List.of(row(0, 7, 0x300, SIGNATURE), row(-1, 7, 0x300, SIGNATURE),
                row(0x100, -1, 0x300, SIGNATURE), row(0x100, 1 << 28, 0x300, SIGNATURE),
                row(0x100, 7, 0, SIGNATURE), row(0x100, 7, -1, SIGNATURE))) {
            fails(() -> Il2CppReferenceGenericCallCatalog.restored(List.of(invalid)));
        }
        fails(() -> Il2CppReferenceGenericCallCatalog.restored(Collections.singletonList(null)));
        check(Il2CppReferenceGenericCallCatalog.restored(List.of(
                row(Long.MAX_VALUE, (1 << 28) - 1, Long.MAX_VALUE, SIGNATURE))).entries().size() == 1,
                "numeric upper bounds");
    }

    private static void testSignature() throws Exception {
        var parsed = ReferenceGenericCallSignature.parse(SIGNATURE);
        check(parsed.returnType().equals("Sample_Item_o*"), "reference return");
        for (String type : List.of("int32_t", "uint32_t", "int64_t", "uint64_t", "intptr_t",
                "uintptr_t", "Il2CppObject*", "Sample_Other_o*")) {
            ReferenceGenericCallSignature.parse(SIGNATURE.replace("int32_t", type));
            checks++;
        }
        for (String invalid : List.of(
                SIGNATURE.replace("Sample_Item_o*", "void"),
                SIGNATURE.replace("Sample_Item_o*", "void*"),
                SIGNATURE.replace("Sample_Item_o*", "Sample_Item_o**"),
                SIGNATURE.replace("reference_generic_call", "shared_generic_call"),
                SIGNATURE.replace("__this", "receiver"),
                SIGNATURE.replace("arg1", "__result"),
                SIGNATURE.replace("arg1", "__this"),
                SIGNATURE.replace("int32_t", "float"),
                SIGNATURE.replace("int32_t", "Sample_Value_o"),
                SIGNATURE.replace("int32_t arg1", "void (*arg1)(void)"),
                SIGNATURE.replace("int32_t arg1", "Sample_Item_o* arg1[2]"),
                SIGNATURE.replace("const MethodInfo*", "MethodInfo*"),
                SIGNATURE.replace("method);", "method, ...);"),
                SIGNATURE + " void extra();",
                SIGNATURE.replace("Sample_Item_o*", "bad;Sample_Item_o*"),
                SIGNATURE.replace("Sample_Item_o*", "\ud800_o*"),
                SIGNATURE.replace("Sample_Item", "Sample_\nItem"))) {
            fails(() -> Il2CppReferenceGenericCallCatalog.restored(List.of(row(0x100, 7, 0x300, invalid))));
        }
        StringBuilder arguments = new StringBuilder();
        for (int index = 1; index <= 6; index++) {
            arguments.append("int32_t arg").append(index).append(", ");
        }
        String eight = "Sample_Item_o* reference_generic_call (Sample_Box_o* __this, " +
                arguments + "const MethodInfo* method);";
        check(ReferenceGenericCallSignature.parse(eight).parameters().size() == 8, "eight physical parameters");
        String nine = eight.replace("const MethodInfo*", "int32_t arg7, const MethodInfo*");
        fails(() -> Il2CppReferenceGenericCallCatalog.restored(List.of(row(0x100, 7, 0x300, nine))));
    }

    private static void testCodec() throws Exception {
        var catalog = Il2CppReferenceGenericCallCatalog.restored(List.of(row(0x100, 7, 0x300, SIGNATURE)));
        byte[] bytes = Il2CppReferenceGenericCallCodec.encode(catalog);
        check(Il2CppReferenceGenericCallCodec.decode(bytes).entries().equals(catalog.entries()), "round trip");
        check(Il2CppReferenceGenericCallCodec.decode(Il2CppReferenceGenericCallCodec.encode(
                Il2CppReferenceGenericCallCatalog.restored(List.of()))).entries().isEmpty(), "empty round trip");
        fails(() -> Il2CppReferenceGenericCallCodec.decode(null));
        for (int length = 0; length < bytes.length; length++) {
            int truncatedLength = length;
            fails(() -> Il2CppReferenceGenericCallCodec.decode(Arrays.copyOf(bytes, truncatedLength)));
        }
        fails(() -> Il2CppReferenceGenericCallCodec.decode(Arrays.copyOf(bytes, bytes.length + 1)));
        for (int[] change : new int[][] { {0, 0}, {4, 2}, {8, -1}, {8, 1_000_001}, {8, 100},
                {20, -1}, {20, 1 << 28}, {32, 0}, {32, -1}, {32, 262_145}, {32, Integer.MAX_VALUE} }) {
            byte[] invalid = bytes.clone();
            ByteBuffer.wrap(invalid).putInt(change[0], change[1]);
            fails(() -> Il2CppReferenceGenericCallCodec.decode(invalid));
        }
        for (int offset : new int[] {12, 24}) {
            byte[] invalid = bytes.clone();
            ByteBuffer.wrap(invalid).putLong(offset, 0);
            fails(() -> Il2CppReferenceGenericCallCodec.decode(invalid));
        }
        byte[] invalidUtf8 = bytes.clone();
        invalidUtf8[36] = (byte) 0xff;
        fails(() -> Il2CppReferenceGenericCallCodec.decode(invalidUtf8));
        var two = Il2CppReferenceGenericCallCatalog.restored(List.of(
                row(0x100, 7, 0x300, SIGNATURE), row(0x120, 8, 0x300, SIGNATURE)));
        byte[] conflicting = Il2CppReferenceGenericCallCodec.encode(two);
        ByteBuffer.wrap(conflicting).putLong(bytes.length, 0x100);
        fails(() -> Il2CppReferenceGenericCallCodec.decode(conflicting));
        var legacy = Il2CppSharedGenericCallCatalog.restored(List.of());
        fails(() -> Il2CppReferenceGenericCallCodec.decode(Il2CppSharedGenericCallCodec.encode(legacy)));
        fails(() -> Il2CppSharedGenericCallCodec.decode(bytes));
    }

    private static void testReader() throws Exception {
        Path path = Files.createTempFile("reference-catalog-test-", ".json");
        try {
            Files.writeString(path, "{\"ScriptMethod\":[]}");
            check(ScriptMethodReader.readAll(path).referenceGenericCalls().isEmpty(), "JSON absent");
            Files.writeString(path, document("[]"));
            check(ScriptMethodReader.readAll(path).referenceGenericCalls().orElseThrow().isEmpty(), "JSON empty");
            String entry = jsonEntry("256", "7", "768", SIGNATURE);
            Files.writeString(path, document("[" + entry + "]"));
            var script = ScriptMethodReader.readAll(path);
            check(Il2CppReferenceGenericCallCatalog.fromScript(script).orElseThrow().entries().size() == 1, "JSON row");
            check(script.sharedGenericCalls().isEmpty(), "old table remains absent");
            for (String invalid : List.of("null", "{}", "[null]", "[3]", "[{}]",
                    "[" + entry.replace("\"MethodSpecIndex\":7,", "") + "]",
                    "[" + entry.replace("\"MethodSpecIndex\":7", "\"MethodSpecIndex\":7,\"MethodSpecIndex\":8") + "]",
                    "[" + entry.replace("\"MethodSpecIndex\":7", "\"Extra\":0,\"Extra\":1,\"MethodSpecIndex\":7") + "]")) {
                Files.writeString(path, document(invalid));
                fails(() -> ScriptMethodReader.readAll(path));
            }
            for (String value : List.of("-1", "1.5", "7.0", "7e0", "\"7\"", "true", "null",
                    "9223372036854775808", "18446744073709551615")) {
                Files.writeString(path, document("[" + jsonEntry(value, "7", "768", SIGNATURE) + "]"));
                fails(() -> ScriptMethodReader.readAll(path));
                Files.writeString(path, document("[" + jsonEntry("256", value, "768", SIGNATURE) + "]"));
                fails(() -> ScriptMethodReader.readAll(path));
                Files.writeString(path, document("[" + jsonEntry("256", "7", value, SIGNATURE) + "]"));
                fails(() -> ScriptMethodReader.readAll(path));
            }
            for (String value : List.of("0", "-0")) {
                Files.writeString(path, document("[" + jsonEntry(value, "7", "768", SIGNATURE) + "]"));
                fails(() -> ScriptMethodReader.readAll(path));
            }
            Files.writeString(path, document("[" + jsonEntry("256", "268435456", "768", SIGNATURE) + "]"));
            fails(() -> ScriptMethodReader.readAll(path));
            Files.writeString(path, "{\"ScriptMethod\":[],\"ScriptReferenceGenericCall\":[],\"ScriptReferenceGenericCall\":[]}");
            fails(() -> ScriptMethodReader.readAll(path));
            Files.writeString(path, document("[" + entry.replace("\"Signature\":\"" + SIGNATURE + "\"", "\"Signature\":42") + "]"));
            fails(() -> ScriptMethodReader.readAll(path));
            Files.writeString(path, document("[" + entry.replace("Sample_Item", "Sample_\\ud800") + "]"));
            fails(() -> ScriptMethodReader.readAll(path));
            Files.writeString(path, document("[" + entry.replace("Sample_Item", "Sample_\\u0000") + "]"));
            fails(() -> ScriptMethodReader.readAll(path));
            Files.writeString(path, document("[" + jsonEntry("256", "0", "768", SIGNATURE) + "]"));
            check(ScriptMethodReader.readAll(path).referenceGenericCalls().orElseThrow().getFirst()
                    .methodSpecIndex() == 0, "method spec zero accepted");
        }
        finally {
            Files.deleteIfExists(path);
        }
    }

    private static void testBounds() throws Exception {
        String largest = SIGNATURE.replace("Sample_Item", "x".repeat(65_536 - SIGNATURE.length() + "Sample_Item".length()));
        var entry = row(0x100, 7, 0x300, largest);
        check(Il2CppReferenceGenericCallCatalog.restored(List.of(entry)).entries().size() == 1, "maximum text size");
        fails(() -> Il2CppReferenceGenericCallCatalog.restored(List.of(row(0x100, 7, 0x300, largest + " "))));
        fails(() -> Il2CppReferenceGenericCallCatalog.restored(Collections.nCopies(1_000_001, entry)));
        fails(() -> Il2CppReferenceGenericCallCatalog.restored(Collections.nCopies(1024, entry)));
        Path path = Files.createTempFile("reference-catalog-budget-", ".json");
        try {
            try (var out = Files.newBufferedWriter(path)) {
                out.write("{\"ScriptMethod\":[],\"ScriptReferenceGenericCall\":[");
                String json = jsonEntry("256", "7", "768", largest);
                for (int index = 0; index < 1024; index++) {
                    if (index != 0) out.write(',');
                    out.write(json);
                }
                out.write("]}");
            }
            fails(() -> ScriptMethodReader.readAll(path));
        }
        finally {
            Files.deleteIfExists(path);
        }
    }

    private static String document(String entries) {
        return "{\"ScriptMethod\":[],\"ScriptReferenceGenericCall\":" + entries + "}";
    }

    private static String jsonEntry(String slot, String spec, String target, String signature) {
        return "{\"MethodInfoAddress\":" + slot + ",\"MethodSpecIndex\":" + spec +
                ",\"MethodAddress\":" + target + ",\"Signature\":\"" + signature + "\"}";
    }

    private static Il2CppReferenceGenericCallCatalog.Entry row(long slot, int spec, long target, String signature) {
        return new Il2CppReferenceGenericCallCatalog.Entry(slot, spec, target, signature);
    }

    private static void fails(Checked action) throws Exception {
        try {
            action.run();
            throw new AssertionError("invalid input was accepted");
        }
        catch (IOException expected) {
            checks++;
        }
    }

    private static void expectImmutable(Runnable action) {
        try {
            action.run();
            throw new AssertionError("mutable catalog");
        }
        catch (UnsupportedOperationException expected) {
            checks++;
        }
    }

    private static void check(boolean condition, String label) {
        if (!condition) throw new AssertionError(label);
        checks++;
    }

    private interface Checked {
        void run() throws Exception;
    }
}
