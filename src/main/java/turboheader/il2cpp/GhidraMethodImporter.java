package turboheader.il2cpp;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.util.exception.InvalidInputException;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.InvalidNameException;
import ghidra.util.task.TaskMonitor;

/** Applies script.json prototypes without reparsing the complete C header. */
public final class GhidraMethodImporter {
    static final CategoryPath OPAQUE = new CategoryPath("/IL2CPP/__signature_opaque");
    static final CategoryPath ALIASES = new CategoryPath("/IL2CPP/__signature_aliases");
    static final CategoryPath SIGNATURES = new CategoryPath("/IL2CPP/__signatures");
    private static final String OWNED_DESCRIPTION =
            "TurboHeader IL2CPP managed type; signature-only opaque C type";
    private static final int SAMPLE_LIMIT = 12;

    private final Program program;
    private final DataTypeManager dtm;
    private final TaskMonitor monitor;
    private final int pointerSize;
    private final Map<String, DataType> cache = new LinkedHashMap<>();
    private final Map<String, Integer> failureCounts = new LinkedHashMap<>();
    private final List<String> failureSamples = new ArrayList<>();
    private int applied;
    private int functionsCreated;
    private int duplicateNamesRepaired;
    private int specializedMethodInfoPointers;
    private int opaquePointerTypes;
    private int assemblyIdentities;

    public GhidraMethodImporter(Program program, TaskMonitor monitor) {
        this.program = program;
        this.dtm = program.getDataTypeManager();
        this.monitor = monitor == null ? TaskMonitor.DUMMY : monitor;
        this.pointerSize = program.getDefaultPointerSize();
    }

    public ImportStats importMethods(List<ScriptMethodReader.ScriptMethod> methods) throws Exception {
        long started = System.nanoTime();
        int transaction = program.startTransaction("TurboHeader IL2CPP method signatures");
        boolean commit = false;
        try {
            monitor.initialize(methods.size());
            for (ScriptMethodReader.ScriptMethod method : methods) {
                monitor.checkCancelled();
                importMethod(method);
                monitor.incrementProgress(1);
            }
            Il2CppProgramFacts.replaceManagedMethods(program, methods);
            commit = true;
        }
        finally {
            program.endTransaction(transaction, commit);
        }
        return new ImportStats(methods.size(), applied, functionsCreated,
                duplicateNamesRepaired, specializedMethodInfoPointers, opaquePointerTypes,
                assemblyIdentities,
                methods.size() - applied, Map.copyOf(failureCounts), List.copyOf(failureSamples),
                System.nanoTime() - started);
    }

    private void importMethod(ScriptMethodReader.ScriptMethod method) {
        CFunctionSignatureParser.ParsedSignature parsed;
        try {
            parsed = CFunctionSignatureParser.parse(method.signature());
        }
        catch (IllegalArgumentException e) {
            fail("invalid signature", method, e.getMessage());
            return;
        }

        if (!typeSignatureMatches(parsed, method.typeSignature())) {
            fail("TypeSignature arity mismatch", method,
                    "expected " + (parsed.parameters().size() + 1) + " ABI entries");
            return;
        }

        FunctionDefinitionDataType signature = new FunctionDefinitionDataType(
                SIGNATURES, "__method_" + Long.toUnsignedString(method.address(), 16), dtm);
        try {
            signature.setReturnType(resolveType(parsed.returnType(), false));
            List<ParameterDefinition> parameters = new ArrayList<>();
            for (CFunctionSignatureParser.Parameter parameter : parsed.parameters()) {
                String comment = isSpecializedMethodInfo(parameter.type())
                        ? "Original IL2CPP parameter type: " + parameter.type()
                        : null;
                parameters.add(new ParameterDefinitionImpl(parameter.name(),
                        resolveType(parameter.type(), true), comment));
            }
            signature.setArguments(parameters.toArray(ParameterDefinition[]::new));
            signature.setVarArgs(parsed.varArgs());

            var defaultConvention = program.getCompilerSpec().getDefaultCallingConvention();
            if (defaultConvention != null) {
                signature.setCallingConvention(defaultConvention.getName());
            }

            duplicateNamesRepaired += parsed.duplicateNamesRepaired();
        }
        catch (UnresolvedByValueTypeException e) {
            fail("unknown by-value type", method, e.getMessage());
            return;
        }
        catch (InvalidInputException e) {
            fail("invalid calling convention", method, e.getMessage());
            return;
        }
        catch (IllegalArgumentException e) {
            fail("invalid data type", method, e.getMessage());
            return;
        }

        Address address;
        try {
            address = program.getImageBase().add(method.address());
        }
        catch (RuntimeException e) {
            fail("invalid address", method, e.getMessage());
            return;
        }

        Function function = program.getFunctionManager().getFunctionAt(address);
        if (function == null) {
            if (!new CreateFunctionCmd(address).applyTo(program, monitor)) {
                fail("function creation failed", method, address.toString());
                return;
            }
            function = program.getFunctionManager().getFunctionAt(address);
            if (function == null) {
                fail("function creation failed", method, address.toString());
                return;
            }
            functionsCreated++;
        }

        String managedName = SymbolUtilities.replaceInvalidChars(method.name(), true);
        try {
            signature.setName(managedName);
        }
        catch (InvalidNameException e) {
            fail("invalid function name", method, e.getMessage());
            return;
        }
        ApplyFunctionSignatureCmd command = new ApplyFunctionSignatureCmd(address, signature,
                SourceType.USER_DEFINED, false, false, DataTypeConflictHandler.REPLACE_HANDLER,
                FunctionRenameOption.RENAME);
        if (!command.applyTo(program, monitor)) {
            fail("signature application failed", method, command.getStatusMsg());
            return;
        }
        if (method.assembly() != null && !method.assembly().isBlank()) {
            function.setComment(MethodAssemblyIdentity.write(function.getComment(), method.assembly()));
            assemblyIdentities++;
        }
        applied++;
    }

    private boolean typeSignatureMatches(CFunctionSignatureParser.ParsedSignature parsed,
            String typeSignature) {
        return typeSignature != null && typeSignature.length() == parsed.parameters().size() + 1;
    }

    DataType resolveType(String declaration, boolean parameter) {
        String text = normalize(declaration);
        int pointers = 0;
        while (text.endsWith("*")) {
            pointers++;
            text = text.substring(0, text.length() - 1).trim();
        }
        if (text.startsWith("struct ")) {
            text = text.substring(7).trim();
        }
        else if (text.startsWith("union ")) {
            text = text.substring(6).trim();
        }
        if (text.isEmpty()) {
            throw new IllegalArgumentException("empty type in '" + declaration + "'");
        }

        String canonical = pointers > 0 ? canonicalMethodInfo(text) : text;
        if (!canonical.equals(text)) {
            specializedMethodInfoPointers++;
            text = canonical;
        }

        String key = text + "#" + pointers;
        DataType cached = cache.get(key);
        if (cached != null) {
            return cached;
        }

        DataType base = resolveKnownBase(text);
        if (base == null) {
            if (pointers == 0) {
                throw new UnresolvedByValueTypeException(text);
            }
            base = createOpaque(text);
        }
        DataType result = base;
        for (int i = 0; i < pointers; i++) {
            result = dtm.getPointer(result, pointerSize);
        }
        if (parameter && result == VoidDataType.dataType) {
            throw new IllegalArgumentException("void parameter");
        }
        cache.put(key, result);
        return result;
    }

    private DataType resolveKnownBase(String name) {
        DataType exact = dtm.getDataType(new DataTypePath(GhidraTypeImporter.ROOT, name));
        if (exact == null) {
            exact = dtm.getDataType(new DataTypePath(OPAQUE, name));
        }
        if (exact == null) {
            exact = dtm.getDataType(new DataTypePath(CategoryPath.ROOT, name));
        }
        if (exact != null) {
            return exact;
        }

        DataType primitive = switch (name.toLowerCase(Locale.ROOT)) {
            case "void" -> VoidDataType.dataType;
            case "bool", "_bool" -> BooleanDataType.dataType;
            case "char", "signed char", "int8_t", "sbyte" -> signed(1);
            case "unsigned char", "uint8_t", "byte" -> unsigned(1);
            case "short", "short int", "signed short", "signed short int", "int16_t" -> signed(2);
            case "unsigned short", "unsigned short int", "uint16_t", "il2cppchar" -> unsigned(2);
            case "int", "signed", "signed int", "int32_t" -> signed(4);
            case "unsigned", "unsigned int", "uint32_t" -> unsigned(4);
            case "long long", "long long int", "signed long long", "int64_t" -> signed(8);
            case "unsigned long long", "unsigned long long int", "uint64_t" -> unsigned(8);
            case "intptr_t", "ssize_t", "ptrdiff_t", "long", "long int", "signed long",
                    "signed long int" -> signed(pointerSize);
            case "uintptr_t", "size_t", "il2cpp_array_size_t", "unsigned long",
                    "unsigned long int" -> unsigned(pointerSize);
            case "float" -> FloatDataType.dataType;
            case "double" -> DoubleDataType.dataType;
            case "wchar_t" -> unsigned(2);
            default -> null;
        };
        if (primitive != null && shouldPreserveAlias(name)) {
            return createAlias(name, primitive);
        }
        return primitive;
    }

    private DataType createAlias(String name, DataType base) {
        DataType existing = dtm.getDataType(new DataTypePath(ALIASES, name));
        if (existing != null) {
            return existing;
        }
        TypedefDataType alias = new TypedefDataType(ALIASES, name, base, dtm);
        return dtm.addDataType(alias, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    private static boolean shouldPreserveAlias(String name) {
        if (name.isEmpty() || !Character.isJavaIdentifierStart(name.charAt(0))) {
            return false;
        }
        for (int i = 1; i < name.length(); i++) {
            if (!Character.isJavaIdentifierPart(name.charAt(i))) {
                return false;
            }
        }
        return switch (name) {
            case "void", "bool", "char", "short", "int", "long", "signed", "unsigned",
                    "float", "double" -> false;
            default -> true;
        };
    }

    private DataType createOpaque(String name) {
        DataType existing = dtm.getDataType(new DataTypePath(OPAQUE, name));
        if (existing != null) {
            return existing;
        }
        StructureDataType opaque = new StructureDataType(OPAQUE, name, 1, dtm);
        opaque.setPackingEnabled(false);
        opaque.setDescription(OWNED_DESCRIPTION);
        opaquePointerTypes++;
        return dtm.addDataType(opaque, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    private static String canonicalMethodInfo(String name) {
        String prefix = "MethodInfo_";
        if (!name.startsWith(prefix) || name.length() == prefix.length()) {
            return name;
        }
        for (int i = prefix.length(); i < name.length(); i++) {
            if (Character.digit(name.charAt(i), 16) < 0) {
                return name;
            }
        }
        return "MethodInfo";
    }

    private static boolean isSpecializedMethodInfo(String declaration) {
        String text = normalize(declaration);
        while (text.endsWith("*")) {
            text = text.substring(0, text.length() - 1).trim();
        }
        return !text.equals("MethodInfo") && canonicalMethodInfo(text).equals("MethodInfo");
    }

    private static String normalize(String declaration) {
        StringBuilder result = new StringBuilder(declaration.length());
        int start = 0;
        while (start < declaration.length()) {
            while (start < declaration.length() && Character.isWhitespace(declaration.charAt(start))) {
                start++;
            }
            int end = start;
            while (end < declaration.length() && !Character.isWhitespace(declaration.charAt(end))) {
                end++;
            }
            if (end == start) {
                break;
            }
            String token = declaration.substring(start, end);
            if (!isQualifier(token)) {
                if (!result.isEmpty() && token.charAt(0) != '*' &&
                        result.charAt(result.length() - 1) != '*') {
                    result.append(' ');
                }
                result.append(token);
            }
            start = end;
        }
        return result.toString().trim();
    }

    private static boolean isQualifier(String token) {
        return token.equals("const") || token.equals("volatile") || token.equals("restrict") ||
                token.equals("__restrict") || token.equals("__restrict__") ||
                token.equals("__cdecl") || token.equals("__stdcall") ||
                token.equals("__fastcall") || token.equals("__thiscall");
    }

    private DataType signed(int bytes) {
        return AbstractIntegerDataType.getSignedDataType(bytes, dtm);
    }

    private DataType unsigned(int bytes) {
        return AbstractIntegerDataType.getUnsignedDataType(bytes, dtm);
    }

    private void fail(String cause, ScriptMethodReader.ScriptMethod method, String detail) {
        failureCounts.merge(cause, 1, Integer::sum);
        if (failureSamples.size() < SAMPLE_LIMIT) {
            failureSamples.add(String.format("0x%x %s: %s%s", method.address(), method.name(),
                    cause, detail == null || detail.isBlank() ? "" : " (" + detail + ")"));
        }
    }

    private static final class UnresolvedByValueTypeException extends IllegalArgumentException {
        UnresolvedByValueTypeException(String type) {
            super(type);
        }
    }

    public record ImportStats(int total, int applied, int functionsCreated,
            int duplicateNamesRepaired, int specializedMethodInfoPointers,
            int opaquePointerTypes, int assemblyIdentities, int failed, Map<String, Integer> failureCounts,
            List<String> failureSamples, long elapsedNanos) {
        public double elapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }
}
