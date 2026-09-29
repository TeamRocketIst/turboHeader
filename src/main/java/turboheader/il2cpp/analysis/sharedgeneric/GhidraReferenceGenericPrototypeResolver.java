package turboheader.il2cpp.analysis.sharedgeneric;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import turboheader.il2cpp.metadata.GhidraMethodImporter;
import turboheader.il2cpp.metadata.ReferenceGenericCallSignature;
import turboheader.il2cpp.types.GhidraTypeImporter;

final class GhidraReferenceGenericPrototypeResolver {
    private GhidraReferenceGenericPrototypeResolver() {
    }

    static Optional<Resolved> resolve(Program program, Function target, String declaration) {
        if (program.getDefaultPointerSize() != 8 || target == null || target.hasVarArgs() ||
                target.hasCustomVariableStorage() || target.hasNoReturn() || target.isThunk()) {
            return Optional.empty();
        }
        try {
            var parsed = ReferenceGenericCallSignature.parse(declaration);
            var convention = program.getCompilerSpec().getDefaultCallingConvention();
            if (convention == null || target.getCallingConvention() == null ||
                    !convention.getName().equals(target.getCallingConvention().getName())) {
                return Optional.empty();
            }
            DataType[] types = new DataType[parsed.parameters().size() + 1];
            types[0] = resolveType(program, parsed.returnType());
            var parameters = new ArrayList<ParameterDefinition>();
            for (int index = 0; index < parsed.parameters().size(); index++) {
                var parameter = parsed.parameters().get(index);
                types[index + 1] = resolveType(program, parameter.type());
                parameters.add(new ParameterDefinitionImpl(parameter.name(), types[index + 1], null));
            }
            VariableStorage[] storage = convention.getStorageLocations(program, types, false);
            if (storage.length != types.length || target.getParameterCount() != parameters.size() ||
                    !compatible(target.getReturnType(), types[0]) ||
                    !sameStorage(storage[0], target.getReturn().getVariableStorage())) {
                return Optional.empty();
            }
            var original = target.getParameters();
            for (int index = 0; index < original.length; index++) {
                if (original[index].isAutoParameter() || !compatible(original[index].getDataType(), types[index + 1]) ||
                        !sameStorage(storage[index + 1], original[index].getVariableStorage())) {
                    return Optional.empty();
                }
            }
            var signature = new FunctionDefinitionDataType(GhidraMethodImporter.signatureCategory(),
                    "__reference_generic_call", program.getDataTypeManager());
            signature.setReturnType(types[0]);
            signature.setArguments(parameters.toArray(ParameterDefinition[]::new));
            signature.setCallingConvention(convention.getName());
            return Optional.of(new Resolved(signature, storage[storage.length - 1].getRegister()));
        }
        catch (IllegalArgumentException | ghidra.util.exception.InvalidInputException e) {
            return Optional.empty();
        }
    }

    private static boolean sameStorage(VariableStorage first, VariableStorage second) {
        return first.isRegisterStorage() && first.getRegister() != null &&
                first.getVarnodes().length == 1 && first.equals(second);
    }

    private static boolean compatible(DataType original, DataType wanted) {
        if (original instanceof TypeDef alias) original = alias.getBaseDataType();
        if (original.getLength() != wanted.getLength()) {
            return false;
        }
        if (wanted instanceof Pointer) return original instanceof Pointer;
        return original instanceof AbstractIntegerDataType first &&
                wanted instanceof AbstractIntegerDataType second && first.isSigned() == second.isSigned();
    }

    private static DataType resolveType(Program program, String declaration) {
        var manager = program.getDataTypeManager();
        if (declaration.endsWith("*")) {
            String name = declaration.substring(0, declaration.length() - 1).trim();
            if (name.equals("const MethodInfo")) name = "MethodInfo";
            DataType type = manager.getDataType(new DataTypePath(GhidraTypeImporter.ROOT, name));
            if (!(type instanceof Structure structure) || structure.getNumDefinedComponents() == 0 ||
                    type.getLength() <= 0) {
                throw new IllegalArgumentException("reference type is not imported");
            }
            List<DataType> matches = new ArrayList<>();
            manager.findDataTypes(name, matches);
            if (matches.size() != 1 || matches.getFirst() != type) {
                throw new IllegalArgumentException("reference type is ambiguous");
            }
            return new PointerDataType(type, program.getDefaultPointerSize(), manager);
        }
        return switch (declaration) {
            case "int32_t" -> AbstractIntegerDataType.getSignedDataType(4, manager);
            case "uint32_t" -> AbstractIntegerDataType.getUnsignedDataType(4, manager);
            case "int64_t", "intptr_t" -> AbstractIntegerDataType.getSignedDataType(8, manager);
            case "uint64_t", "uintptr_t" -> AbstractIntegerDataType.getUnsignedDataType(8, manager);
            default -> throw new IllegalArgumentException("unsupported reference argument type");
        };
    }

    record Resolved(FunctionSignature signature, Register methodInfo) {
    }
}
