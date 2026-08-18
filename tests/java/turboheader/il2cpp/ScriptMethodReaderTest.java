package turboheader.il2cpp;

import java.nio.file.Files;
import java.nio.file.Path;

public final class ScriptMethodReaderTest {
    public static void main(String[] args) throws Exception {
        Path fixture = Files.createTempFile("turboheader-script-methods", ".json");
        try {
            Files.writeString(fixture, """
                    {"Ignored":{"large":[1,2,3]},"ScriptMethod":[
                      {"Address":16,"Name":"A$$Run","Signature":"void A__Run (const MethodInfo* method);","TypeSignature":"vi"},
                      {"TypeSignature":"vii","Signature":"void B__Set (int32_t value, const MethodInfo* method);","Name":"B$$Set","Address":32,"Assembly":"Assembly-CSharp"}
                    ],"ScriptMetadata":[
                      {"Address":48,"Name":"Fixture.TypeInfo","Signature":"A_c*"},
                      {"Signature":null,"Name":"Fixture.Field","Address":56}
                    ],"ScriptMetadataMethod":[
                      {"Address":60,"Name":"Method$List<Fixture>.get_Item()","MethodAddress":256},
                      {"MethodAddress":0,"Name":"Method$List<Fixture>.get_Count()","Address":62}
                    ],"ScriptString":[
                      {"Address":64,"Value":"Attempt "},
                      {"Value":"line\\n\\t\\\"\\\\é","Address":72}
                    ],"Addresses":[16,32]}
                    """);
            var data = ScriptMethodReader.readAll(fixture);
            var methods = data.methods();
            check(methods.size() == 2, "method count");
            check(methods.get(0).address() == 16 && methods.get(0).name().equals("A$$Run"),
                    "first method");
            check(methods.get(1).signature().startsWith("void B__Set"), "property order");
            check(methods.get(0).assembly() == null, "legacy assembly omission");
            check(methods.get(1).assembly().equals("Assembly-CSharp"), "assembly identity");
            check(data.metadata().size() == 2, "metadata count");
            check(data.metadata().get(0).address() == 48 &&
                    data.metadata().get(0).signature().equals("A_c*"), "typed metadata");
            check(data.metadata().get(1).signature() == null, "untyped metadata");
            check(data.metadataMethods().size() == 2, "method metadata count");
            check(data.metadataMethods().get(0).address() == 60 &&
                    data.metadataMethods().get(0).methodAddress() == 256,
                    "method metadata address");
            check(data.metadataMethods().get(1).methodAddress() == 0,
                    "unresolved method metadata address");
            check(data.strings().size() == 2, "string count");
            check(data.strings().get(0).address() == 64 &&
                    data.strings().get(0).value().equals("Attempt "), "first string");
            check(data.strings().get(1).value().equals("line\n\t\"\\é"),
                    "escaped string");
        }
        finally {
            Files.deleteIfExists(fixture);
        }

        expectFailure("{\"ScriptMethod\":[],\"ScriptString\":[],\"ScriptString\":[]}",
                "duplicate string table");
        expectFailure("{\"ScriptMethod\":[],\"ScriptString\":[{\"Address\":1}]}",
                "missing string value");
        expectFailure("{\"ScriptMethod\":[],\"ScriptString\":[{\"Address\":-1,\"Value\":\"x\"}]}",
                "negative string address");
        expectFailure("{\"ScriptMethod\":[],\"ScriptMetadataMethod\":[{\"Address\":1,\"Name\":\"M\"}]}",
                "missing metadata method address");
        expectFailure("{\"ScriptMethod\":[],\"ScriptMetadataMethod\":[],\"ScriptMetadataMethod\":[]}",
                "duplicate metadata method table");

        if (args.length == 1) {
            var methods = ScriptMethodReader.read(Path.of(args[0]));
            check(methods.size() == 99_205, "Ghosts ScriptMethod count");
            int repaired = 0;
            for (var method : methods) {
                var parsed = CFunctionSignatureParser.parse(method.signature());
                check(method.typeSignature().length() == parsed.parameters().size() + 1,
                        "TypeSignature arity at 0x" + Long.toHexString(method.address()));
                repaired += parsed.duplicateNamesRepaired();
            }
            check(repaired > 0, "Ghosts duplicate-name fixture");
        }
        System.out.println("script method reader tests passed");
    }

    private static void expectFailure(String json, String label) throws Exception {
        Path fixture = Files.createTempFile("turboheader-invalid-script", ".json");
        try {
            Files.writeString(fixture, json);
            try {
                ScriptMethodReader.readAll(fixture);
                throw new AssertionError(label);
            }
            catch (java.io.IOException expected) {
                // Expected validation failure.
            }
        }
        finally {
            Files.deleteIfExists(fixture);
        }
    }

    private static void check(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }
}
