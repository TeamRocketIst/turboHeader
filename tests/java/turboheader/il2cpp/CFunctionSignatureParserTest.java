package turboheader.il2cpp;

import java.util.List;

public final class CFunctionSignatureParserTest {
    public static void main(String[] args) {
        basicIl2CppSignature();
        unnamedAndDuplicateParameters();
        nestedDeclaratorsAndVarArgs();
        voidAndTrailingSemicolon();
        invalidDeclarationsFail();
        System.out.println("C function signature parser tests passed");
    }

    private static void basicIl2CppSignature() {
        var signature = CFunctionSignatureParser.parse(
                "void Handler___ctor (Handler_o* __this, intptr_t method, " +
                "const MethodInfo* method_1);");
        check(signature.returnType().equals("void"), "return type");
        check(signature.functionName().equals("Handler___ctor"), "function name");
        check(signature.parameters().equals(List.of(
                new CFunctionSignatureParser.Parameter("Handler_o*", "__this"),
                new CFunctionSignatureParser.Parameter("intptr_t", "method"),
                new CFunctionSignatureParser.Parameter("const MethodInfo*", "method_1"))),
                "IL2CPP parameters");
        check(!signature.varArgs(), "non-variadic signature");
    }

    private static void unnamedAndDuplicateParameters() {
        var signature = CFunctionSignatureParser.parse(
                "int32_t probe (int32_t, unsigned int, Value_o value, " +
                "Value_o value_1, Value_o value, float arg0)");
        check(signature.parameters().equals(List.of(
                new CFunctionSignatureParser.Parameter("int32_t", "arg0"),
                new CFunctionSignatureParser.Parameter("unsigned int", "arg1"),
                new CFunctionSignatureParser.Parameter("Value_o", "value"),
                new CFunctionSignatureParser.Parameter("Value_o", "value_1"),
                new CFunctionSignatureParser.Parameter("Value_o", "value_2"),
                new CFunctionSignatureParser.Parameter("float", "arg0_1"))),
                "unnamed and duplicate allocation");
    }

    private static void nestedDeclaratorsAndVarArgs() {
        var signature = CFunctionSignatureParser.parse(
                "void invoke (void (*callback)(int32_t, float), int32_t values[4], ...);");
        check(signature.parameters().equals(List.of(
                new CFunctionSignatureParser.Parameter("void (*)(int32_t, float)", "callback"),
                new CFunctionSignatureParser.Parameter("int32_t[4]", "values"))),
                "nested declarators");
        check(signature.varArgs(), "variadic signature");
    }

    private static void voidAndTrailingSemicolon() {
        var withVoid = CFunctionSignatureParser.parse("uintptr_t empty (void);   ");
        check(withVoid.parameters().isEmpty(), "void parameter list");
        check(!withVoid.varArgs(), "void is not varargs");

        var empty = CFunctionSignatureParser.parse("void empty2 ()");
        check(empty.parameters().isEmpty(), "empty parameter list");
    }

    private static void invalidDeclarationsFail() {
        expectFailure("void missing");
        expectFailure("void broken (int32_t value");
        expectFailure("void broken2 (..., int32_t value)");
        expectFailure("void broken3 (int32_t value,, float other)");
    }

    private static void expectFailure(String declaration) {
        try {
            CFunctionSignatureParser.parse(declaration);
            throw new AssertionError("expected parse failure: " + declaration);
        }
        catch (IllegalArgumentException expected) {
            // expected
        }
    }

    private static void check(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }
}
