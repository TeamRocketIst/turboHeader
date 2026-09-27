package turboheader.il2cpp.analysis.sharedgeneric;

import java.util.ArrayList;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;

import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import turboheader.il2cpp.metadata.GhidraMethodImporter;
import turboheader.il2cpp.metadata.SharedGenericCallSignature;

final class GhidraSharedGenericPrototypeResolver {
    private GhidraSharedGenericPrototypeResolver() {
    }

    static FunctionSignature resolve(Program program, long methodInfoAddress,
            SharedGenericCallSignature prototype) throws InvalidInputException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(prototype, "prototype");
        if (resultAlignment(program, prototype).isEmpty()) {
            throw new IllegalArgumentException(
                    "shared-generic value result type is not imported");
        }
        var types = new GhidraMethodImporter(program, TaskMonitor.DUMMY);
        var signature = new FunctionDefinitionDataType(
                GhidraMethodImporter.signatureCategory(),
                "__shared_generic_" + Long.toUnsignedString(methodInfoAddress, 16),
                program.getDataTypeManager());
        signature.setReturnType(types.resolveType(prototype.returnType(), false));

        var parameters = new ArrayList<ParameterDefinition>();
        for (var parameter : prototype.parameters()) {
            parameters.add(new ParameterDefinitionImpl(parameter.name(),
                    types.resolveType(parameter.type(), true), null));
        }
        signature.setArguments(parameters.toArray(ParameterDefinition[]::new));

        var convention = program.getCompilerSpec().getDefaultCallingConvention();
        if (convention != null) {
            signature.setCallingConvention(convention.getName());
        }
        return signature;
    }

    static Optional<CallStorage> resolveStorage(Program program,
            SharedGenericCallSignature prototype) {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(prototype, "prototype");
        OptionalInt resultAlignment = resultAlignment(program, prototype);
        if (resultAlignment.isEmpty()) {
            return Optional.empty();
        }
        var convention = program.getCompilerSpec().getDefaultCallingConvention();
        if (convention == null) {
            return Optional.empty();
        }

        var resolver = new GhidraMethodImporter(program, TaskMonitor.DUMMY);
        DataType[] types = new DataType[prototype.parameters().size() + 1];
        types[0] = VoidDataType.dataType;
        try {
            for (int index = 0; index < prototype.parameters().size(); index++) {
                types[index + 1] = abiType(program, resolver,
                        prototype.parameters().get(index).type());
            }
        }
        catch (IllegalArgumentException e) {
            return Optional.empty();
        }

        var locations = convention.getStorageLocations(program, types, false);
        if (locations.length != types.length) {
            return Optional.empty();
        }
        int resultIndex = prototype.parameters().size() - 1;
        int methodInfoIndex = prototype.parameters().size();
        if (!locations[resultIndex].isRegisterStorage() ||
                !locations[methodInfoIndex].isRegisterStorage()) {
            return Optional.empty();
        }
        Register result = locations[resultIndex].getRegister();
        Register methodInfo = locations[methodInfoIndex].getRegister();
        if (result == null || methodInfo == null) {
            return Optional.empty();
        }
        return Optional.of(new CallStorage(result, methodInfo,
                resultAlignment.getAsInt()));
    }

    private static OptionalInt resultAlignment(Program program,
            SharedGenericCallSignature prototype) {
        if (!prototype.hasValueResult()) {
            return OptionalInt.of(program.getDefaultPointerSize());
        }
        try {
            var resolver = new GhidraMethodImporter(program, TaskMonitor.DUMMY);
            DataType pointee = abiType(program, resolver,
                    prototype.resultPointeeType());
            int alignment = program.getDataTypeManager().getDataOrganization()
                    .getAlignment(pointee);
            return alignment > 0 ? OptionalInt.of(alignment) : OptionalInt.empty();
        }
        catch (IllegalArgumentException e) {
            return OptionalInt.empty();
        }
    }

    private static DataType abiType(Program program, GhidraMethodImporter resolver,
            String declaration) {
        String type = normalize(declaration);
        if (type.indexOf('*') >= 0) {
            return new PointerDataType(VoidDataType.dataType,
                    program.getDefaultPointerSize(), program.getDataTypeManager());
        }
        return switch (type.toLowerCase(Locale.ROOT)) {
            case "void" -> VoidDataType.dataType;
            case "bool", "_bool" -> BooleanDataType.dataType;
            case "char", "signed char", "int8_t", "sbyte" ->
                AbstractIntegerDataType.getSignedDataType(1, program.getDataTypeManager());
            case "unsigned char", "uint8_t", "byte" ->
                AbstractIntegerDataType.getUnsignedDataType(1, program.getDataTypeManager());
            case "short", "short int", "signed short", "signed short int", "int16_t" ->
                AbstractIntegerDataType.getSignedDataType(2, program.getDataTypeManager());
            case "unsigned short", "unsigned short int", "uint16_t", "il2cppchar" ->
                AbstractIntegerDataType.getUnsignedDataType(2, program.getDataTypeManager());
            case "int", "signed", "signed int", "int32_t" ->
                AbstractIntegerDataType.getSignedDataType(4, program.getDataTypeManager());
            case "unsigned", "unsigned int", "uint32_t" ->
                AbstractIntegerDataType.getUnsignedDataType(4, program.getDataTypeManager());
            case "long long", "long long int", "signed long long", "int64_t" ->
                AbstractIntegerDataType.getSignedDataType(8, program.getDataTypeManager());
            case "unsigned long long", "unsigned long long int", "uint64_t" ->
                AbstractIntegerDataType.getUnsignedDataType(8, program.getDataTypeManager());
            case "intptr_t", "ssize_t", "ptrdiff_t", "long", "long int", "signed long",
                    "signed long int" -> AbstractIntegerDataType.getSignedDataType(
                        program.getDefaultPointerSize(), program.getDataTypeManager());
            case "uintptr_t", "size_t", "il2cpp_array_size_t", "unsigned long",
                    "unsigned long int" -> AbstractIntegerDataType.getUnsignedDataType(
                        program.getDefaultPointerSize(), program.getDataTypeManager());
            case "float" -> FloatDataType.dataType;
            case "double" -> DoubleDataType.dataType;
            case "wchar_t" -> AbstractIntegerDataType.getUnsignedDataType(
                    2, program.getDataTypeManager());
            default -> resolver.resolveType(declaration, true);
        };
    }

    private static String normalize(String declaration) {
        StringBuilder result = new StringBuilder(declaration.length());
        int start = 0;
        while (start < declaration.length()) {
            while (start < declaration.length() &&
                    Character.isWhitespace(declaration.charAt(start))) {
                start++;
            }
            int end = start;
            while (end < declaration.length() &&
                    !Character.isWhitespace(declaration.charAt(end))) {
                end++;
            }
            if (end == start) {
                break;
            }
            String token = declaration.substring(start, end);
            if (!isIgnoredToken(token)) {
                if (!result.isEmpty()) {
                    result.append(' ');
                }
                result.append(token);
            }
            start = end;
        }
        return result.toString();
    }

    private static boolean isIgnoredToken(String token) {
        return token.equals("const") || token.equals("volatile") ||
                token.equals("restrict") || token.equals("__restrict") ||
                token.equals("__restrict__") || token.equals("struct") ||
                token.equals("union") || token.equals("enum");
    }

    record CallStorage(Register result, Register methodInfo, int resultAlignment) {
        CallStorage {
            Objects.requireNonNull(result, "result");
            Objects.requireNonNull(methodInfo, "methodInfo");
            if (resultAlignment <= 0) {
                throw new IllegalArgumentException("invalid result alignment");
            }
        }
    }
}
