package turboheader.il2cpp.metadata;

import java.util.List;

import turboheader.il2cpp.types.CFunctionSignatureParser;

public record SharedGenericCallSignature(String declaration, String returnType,
        List<CFunctionSignatureParser.Parameter> parameters) {
    public SharedGenericCallSignature {
        if (declaration == null || declaration.isBlank() ||
                returnType == null || returnType.isBlank()) {
            throw new IllegalArgumentException("invalid shared-generic signature");
        }
        parameters = List.copyOf(parameters);
    }

    public static SharedGenericCallSignature parse(String declaration) {
        var parsed = CFunctionSignatureParser.parse(declaration);
        if (!parsed.returnType().equals("void") ||
                !parsed.functionName().equals("shared_generic_call") ||
                parsed.varArgs() || parsed.parameters().size() < 2) {
            throw new IllegalArgumentException("invalid shared-generic signature");
        }
        var result = parsed.parameters().get(parsed.parameters().size() - 2);
        var method = parsed.parameters().getLast();
        if (!result.name().equals("__result") || pointerDepth(result.type()) < 2) {
            throw new IllegalArgumentException("invalid shared-generic result parameter");
        }
        if (!method.type().equals("const MethodInfo*") ||
                !method.name().equals("method")) {
            throw new IllegalArgumentException("invalid shared-generic MethodInfo parameter");
        }
        return new SharedGenericCallSignature(declaration, parsed.returnType(),
                parsed.parameters());
    }

    private static int pointerDepth(String type) {
        int result = 0;
        for (int index = 0; index < type.length(); index++) {
            if (type.charAt(index) == '*') {
                result++;
            }
        }
        return result;
    }
}
