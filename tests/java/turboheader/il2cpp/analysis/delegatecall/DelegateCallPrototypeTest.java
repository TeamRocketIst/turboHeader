package turboheader.il2cpp.analysis.delegatecall;

public final class DelegateCallPrototypeTest {
    private static final int TYPE_ID = 7;
    private static final String OBJECT_TYPE = "System_Action_int__o*";

    public static void main(String[] args) {
        parsesGeneratedNativeSignature();
        parsesRenamedRuntimeParameter();
        rejectsUnexpectedAbiShapes();
        System.out.println("delegate-call prototype tests passed");
    }

    private static void parsesGeneratedNativeSignature() {
        var prototype = DelegateCallPrototype.parse(TYPE_ID, OBJECT_TYPE,
                "bool delegate_invoke (Il2CppMethodPointer methodCode, int32_t value, " +
                "const MethodInfo* method);");
        require(prototype.typeId() == TYPE_ID, "TypeId");
        require(prototype.objectType().equals(OBJECT_TYPE), "object type");
        require(prototype.signature().startsWith("bool delegate_invoke"), "signature");
        require(prototype.returnType().equals("bool"), "return type");
        require(prototype.parameters().size() == 3, "parameter count");
        require(prototype.parameters().get(1).type().equals("int32_t"),
                "managed argument type");
    }

    private static void parsesRenamedRuntimeParameter() {
        for (String name : new String[] { "method_1", "method_2", "runtimeInfo" }) {
            String signature = "void delegate_invoke (Il2CppMethodPointer methodCode, " +
                    "int32_t method, int32_t method_0, const MethodInfo* " + name + ");";
            var prototype = DelegateCallPrototype.parse(TYPE_ID, OBJECT_TYPE, signature);
            require(prototype.signature().equals(signature), "signature preserved");
            require(prototype.parameters().get(1).name().equals("method"),
                    "managed parameter name preserved");
            require(prototype.parameters().getLast().name().equals(name),
                    "runtime parameter name preserved");
            require(prototype.parameters().getLast().type().equals("const MethodInfo*"),
                    "runtime parameter type preserved");
        }
    }

    private static void rejectsUnexpectedAbiShapes() {
        reject("void wrong_name (Il2CppMethodPointer methodCode, const MethodInfo* method);");
        reject("void delegate_invoke (Il2CppMethodPointer methodCode, ...);");
        reject("void delegate_invoke (void* receiver, const MethodInfo* method);");
        reject("void delegate_invoke (Il2CppMethodPointer methodCode, void* info);");
        reject("void delegate_invoke (Il2CppMethodPointer methodCode);");
        reject("void delegate_invoke (Il2CppMethodPointer methodCode, const MethodInfo* method_1, int32_t value);");
        reject("void delegate_invoke (Il2CppMethodPointer methodCode, MethodInfo* method_1);");
        reject("void delegate_invoke (Il2CppMethodPointer methodCode, const MethodInfo** method_1);");
        reject("void delegate_invoke (Il2CppMethodPointer methodCode, const MethodInfo* method_1, ...);");
        reject("void delegate_invoke (Il2CppMethodPointer methodCode, const MethodInfo* method_1); extra");
        reject("void delegate_invoke (Il2CppMethodPointer methodCode, const MethodInfo* method_1");
    }

    private static void reject(String signature) {
        try {
            DelegateCallPrototype.parse(TYPE_ID, OBJECT_TYPE, signature);
            throw new AssertionError("invalid signature accepted: " + signature);
        }
        catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
