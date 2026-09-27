package turboheader.il2cpp.analysis.delegatecall;

public final class DelegateCallPrototypeTest {
    private static final int TYPE_ID = 7;
    private static final String OBJECT_TYPE = "System_Action_int__o*";

    public static void main(String[] args) {
        parsesGeneratedNativeSignature();
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

    private static void rejectsUnexpectedAbiShapes() {
        reject("void wrong_name (Il2CppMethodPointer methodCode, const MethodInfo* method);");
        reject("void delegate_invoke (Il2CppMethodPointer methodCode, ...);");
        reject("void delegate_invoke (void* receiver, const MethodInfo* method);");
        reject("void delegate_invoke (Il2CppMethodPointer methodCode, void* info);");
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
