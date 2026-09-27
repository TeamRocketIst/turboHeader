package turboheader.il2cpp.analysis.delegatecall;

import java.util.List;

import turboheader.il2cpp.types.CFunctionSignatureParser;

public record DelegateCallPrototype(int typeId, String objectType, String signature,
        String returnType, List<CFunctionSignatureParser.Parameter> parameters) {
    public DelegateCallPrototype {
        if (typeId < 0 || objectType == null || objectType.isBlank() ||
                signature == null || signature.isBlank() ||
                returnType == null || returnType.isBlank()) {
            throw new IllegalArgumentException("invalid delegate-call prototype");
        }
        parameters = List.copyOf(parameters);
    }

    public static DelegateCallPrototype parse(int typeId, String objectType,
            String signature) {
        var parsed = CFunctionSignatureParser.parse(signature);
        if (!parsed.functionName().equals("delegate_invoke")) {
            throw new IllegalArgumentException("unexpected delegate function name");
        }
        if (parsed.varArgs() || parsed.parameters().size() < 2) {
            throw new IllegalArgumentException("invalid delegate parameter list");
        }

        var first = parsed.parameters().getFirst();
        var last = parsed.parameters().getLast();
        if (!first.type().equals("Il2CppMethodPointer") ||
                !first.name().equals("methodCode")) {
            throw new IllegalArgumentException("invalid delegate method-code parameter");
        }
        if (!last.type().equals("const MethodInfo*") || !last.name().equals("method")) {
            throw new IllegalArgumentException("invalid delegate MethodInfo parameter");
        }
        return new DelegateCallPrototype(typeId, objectType, signature,
                parsed.returnType(), parsed.parameters());
    }
}
