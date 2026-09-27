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
        if (!result.name().equals("__result") || pointerDepth(result.type()) < 1 ||
                resultPointeeType(result.type()).equals("void")) {
            throw new IllegalArgumentException("invalid shared-generic result parameter");
        }
        if (!method.type().equals("const MethodInfo*") ||
                !method.name().equals("method")) {
            throw new IllegalArgumentException("invalid shared-generic MethodInfo parameter");
        }
        return new SharedGenericCallSignature(declaration, parsed.returnType(),
                parsed.parameters());
    }

    public CFunctionSignatureParser.Parameter resultParameter() {
        return parameters.get(parameters.size() - 2);
    }

    public boolean hasValueResult() {
        return pointerDepth(resultParameter().type()) == 1;
    }

    public String resultPointeeType() {
        return resultPointeeType(resultParameter().type());
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

    private static String resultPointeeType(String type) {
        int end = type.length();
        while (end > 0 && Character.isWhitespace(type.charAt(end - 1))) {
            end--;
        }
        if (end == 0 || type.charAt(end - 1) != '*') {
            return "";
        }
        String result = type.substring(0, end - 1).trim();
        if (result.startsWith("const ")) {
            result = result.substring(6).trim();
        }
        if (result.startsWith("volatile ")) {
            result = result.substring(9).trim();
        }
        return result;
    }
}
