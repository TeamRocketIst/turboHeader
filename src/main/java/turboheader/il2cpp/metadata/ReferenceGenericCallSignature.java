package turboheader.il2cpp.metadata;

import java.util.List;
import java.util.Set;

import turboheader.il2cpp.types.CFunctionSignatureParser;

public record ReferenceGenericCallSignature(String returnType,
        List<CFunctionSignatureParser.Parameter> parameters) {
    private static final Set<String> INTEGERS = Set.of(
            "int32_t", "uint32_t", "int64_t", "uint64_t", "intptr_t", "uintptr_t");

    public ReferenceGenericCallSignature {
        parameters = List.copyOf(parameters);
    }

    public static ReferenceGenericCallSignature parse(String declaration) {
        var parsed = CFunctionSignatureParser.parse(declaration);
        var parameters = parsed.parameters();
        if (!parsed.functionName().equals("reference_generic_call") || parsed.varArgs() ||
                parsed.duplicateNamesRepaired() != 0 || !isReference(parsed.returnType()) ||
                parameters.size() < 2 || parameters.size() > 8) {
            throw new IllegalArgumentException("invalid reference-generic signature");
        }
        var receiver = parameters.getFirst();
        var method = parameters.getLast();
        if (!isReference(receiver.type()) || !receiver.name().equals("__this") ||
                !method.type().equals("const MethodInfo*") || !method.name().equals("method")) {
            throw new IllegalArgumentException("invalid reference-generic receiver or MethodInfo");
        }
        for (int index = 1; index < parameters.size() - 1; index++) {
            var parameter = parameters.get(index);
            if (!parameter.name().equals("arg" + index) ||
                    (!isReference(parameter.type()) && !INTEGERS.contains(parameter.type()))) {
                throw new IllegalArgumentException("unsupported reference-generic argument");
            }
        }
        return new ReferenceGenericCallSignature(parsed.returnType(), parameters);
    }

    private static boolean isReference(String type) {
        if (!type.endsWith("*")) {
            return false;
        }
        String name = type.substring(0, type.length() - 1).trim();
        if (!name.equals("Il2CppObject") && !name.endsWith("_o")) {
            return false;
        }
        for (int index = 0; index < name.length(); index++) {
            char value = name.charAt(index);
            boolean letter = value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z';
            boolean digit = index > 0 && value >= '0' && value <= '9';
            if (!letter && !digit && value != '_') {
                return false;
            }
        }
        return true;
    }
}
