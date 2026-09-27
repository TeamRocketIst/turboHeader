package turboheader.il2cpp.metadata;

import java.nio.file.Files;
import java.nio.file.Path;

import turboheader.il2cpp.types.CFunctionSignatureParser;

public final class ScriptMethodReaderTest {
    public static void main(String[] args) throws Exception {
        Path fixture = Files.createTempFile("turboheader-script-methods", ".json");
        try {
            Files.writeString(fixture, """
                    {"Ignored":{"large":[1,2,3]},"ScriptMethod":[
                      {"Address":16,"Name":"A$$Run","Signature":"void A__Run (const MethodInfo* method);","TypeSignature":"vi"},
                      {"TypeSignature":"vii","Signature":"void B__Set (int32_t value, const MethodInfo* method);","Name":"B$$Set","Address":32,"Assembly":"Assembly-CSharp"}
                    ],"ScriptMetadata":[
                      {"Address":48,"Name":"Fixture.TypeInfo","Signature":"A_c*","TypeId":4},
                      {"Signature":"I_c*","Name":"Fixture.Interface_TypeInfo","Address":56,"TypeId":2},
                      {"Signature":null,"Name":"Fixture.Field","Address":58}
                    ],"ScriptMetadataMethod":[
                      {"Address":60,"Name":"Method$List<Fixture>.get_Item()","MethodAddress":256},
                      {"MethodAddress":0,"Name":"Method$List<Fixture>.get_Count()","Address":62}
                    ],"ScriptString":[
                      {"Address":64,"Value":"Attempt "},
                      {"Value":"line\\n\\t\\\"\\\\é","Address":72}
                    ],"Addresses":[16,32],"ScriptInterfaceDispatch":[
                      {"ReceiverTypeId":4,"InterfaceTypeId":2,"InterfaceSlot":0,"MethodAddress":16,"Signature":"void A__Run (const MethodInfo* method);"}
                    ],"ScriptDelegateSignature":[
                      {"TypeId":7,"ObjectType":"System_Action_int__o*","Signature":"void delegate_invoke (Il2CppMethodPointer methodCode, int32_t value, const MethodInfo* method);"}
                    ],"ScriptSharedGenericCall":[
                      {"MethodInfoAddress":96,"MethodAddress":128,"Signature":"void shared_generic_call (Fixture_List_o* __this, int32_t index, Fixture_Item_o** __result, const MethodInfo* method);"}
                    ]}
                    """);
            var data = ScriptMethodReader.readAll(fixture);
            var methods = data.methods();
            check(methods.size() == 2, "method count");
            check(methods.get(0).address() == 16 && methods.get(0).name().equals("A$$Run"),
                    "first method");
            check(methods.get(1).signature().startsWith("void B__Set"), "property order");
            check(methods.get(0).assembly() == null, "legacy assembly omission");
            check(methods.get(1).assembly().equals("Assembly-CSharp"), "assembly identity");
            check(data.metadata().size() == 3, "metadata count");
            check(data.metadata().get(0).address() == 48 &&
                    data.metadata().get(0).signature().equals("A_c*"), "typed metadata");
            check(data.metadata().get(0).typeId() == 4, "metadata type identity");
            check(data.metadata().get(2).signature() == null, "untyped metadata");
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
            check(data.interfaceDispatch().orElseThrow().size() == 1,
                    "interface dispatch count");
            check(data.interfaceDispatch().orElseThrow().get(0).methodAddress() == 16,
                    "interface dispatch target");
            check(data.delegateSignatures().orElseThrow().size() == 1,
                    "delegate signature count");
            check(data.delegateSignatures().orElseThrow().get(0).typeId() == 7,
                    "delegate signature TypeId");
            check(data.sharedGenericCalls().orElseThrow().size() == 1,
                    "shared generic call count");
            check(data.sharedGenericCalls().orElseThrow().get(0).methodInfoAddress() == 96,
                    "shared generic MethodInfo address");
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
        expectFailure("{\"ScriptMethod\":[],\"ScriptInterfaceDispatch\":[],\"ScriptInterfaceDispatch\":[]}",
                "duplicate interface dispatch table");
        expectFailure("{\"ScriptMethod\":[],\"ScriptDelegateSignature\":[],\"ScriptDelegateSignature\":[]}",
                "duplicate delegate signature table");
        expectFailure("{\"ScriptMethod\":[],\"ScriptSharedGenericCall\":[],\"ScriptSharedGenericCall\":[]}",
                "duplicate shared generic call table");
        expectFailure("{\"ScriptMethod\":[],\"ScriptInterfaceDispatch\":[{" +
                "\"ReceiverTypeId\":1,\"InterfaceTypeId\":2,\"InterfaceSlot\":-1," +
                "\"MethodAddress\":16,\"Signature\":\"void A__Run ();\"}]}",
                "negative interface slot");
        expectFailure("{\"ScriptMethod\":[],\"ScriptInterfaceDispatch\":[{" +
                "\"ReceiverTypeId\":1,\"ReceiverTypeId\":1,\"InterfaceTypeId\":2," +
                "\"InterfaceSlot\":0,\"MethodAddress\":16," +
                "\"Signature\":\"void A__Run ();\"}]}",
                "duplicate dispatch field");
        expectFailure("{\"ScriptMethod\":[],\"ScriptDelegateSignature\":[{" +
                "\"TypeId\":-1,\"ObjectType\":\"Action_o*\"," +
                "\"Signature\":\"void delegate_invoke ();\"}]}",
                "negative delegate TypeId");
        expectFailure("{\"ScriptMethod\":[],\"ScriptDelegateSignature\":[{" +
                "\"TypeId\":1,\"ObjectType\":\"Action_o*\",\"ObjectType\":\"Other_o*\"," +
                "\"Signature\":\"void delegate_invoke ();\"}]}",
                "duplicate delegate field");
        expectFailure("{\"ScriptMethod\":[],\"ScriptDelegateSignature\":[{" +
                "\"TypeId\":1,\"ObjectType\":\"Action\\u0001_o*\"," +
                "\"Signature\":\"void delegate_invoke ();\"}]}",
                "delegate type control character");
        expectFailure("{\"ScriptMethod\":[],\"ScriptSharedGenericCall\":[{" +
                "\"MethodInfoAddress\":0,\"MethodAddress\":32," +
                "\"Signature\":\"void shared_generic_call ();\"}]}",
                "zero shared generic MethodInfo address");
        expectFailure("{\"ScriptMethod\":[],\"ScriptSharedGenericCall\":[{" +
                "\"MethodInfoAddress\":16,\"MethodAddress\":32,\"MethodAddress\":48," +
                "\"Signature\":\"void shared_generic_call ();\"}]}",
                "duplicate shared generic field");

        if (args.length == 1) {
            var methods = ScriptMethodReader.read(Path.of(args[0]));
            check(!methods.isEmpty(), "method table");
            int repaired = 0;
            for (var method : methods) {
                var parsed = CFunctionSignatureParser.parse(method.signature());
                check(method.typeSignature().length() == parsed.parameters().size() + 1,
                        "TypeSignature arity at 0x" + Long.toHexString(method.address()));
                repaired += parsed.duplicateNamesRepaired();
            }
            check(repaired > 0, "duplicate-name fixture");
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
