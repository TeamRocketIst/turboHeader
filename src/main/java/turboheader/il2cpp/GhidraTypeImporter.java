package turboheader.il2cpp;

import static turboheader.il2cpp.TypeModel.FieldDef;
import static turboheader.il2cpp.TypeModel.LayoutEvidence;
import static turboheader.il2cpp.TypeModel.Model;
import static turboheader.il2cpp.TypeModel.StructDef;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Imports an already-parsed IL2CPP model with one transaction and bulk shell creation.
 * Explicit-layout overlaps are represented as unions, including shifted overlap wrappers.
 */
public final class GhidraTypeImporter {
    public static final CategoryPath ROOT = new CategoryPath("/IL2CPP");
    private static final CategoryPath OPAQUE = new CategoryPath("/IL2CPP/__opaque");
    private static final CategoryPath OVERLAPS = new CategoryPath("/IL2CPP/__overlaps");
    private static final CategoryPath FUNCTIONS = new CategoryPath("/IL2CPP/__functions");
    private static final CategoryPath SIGNATURE_ALIASES =
            new CategoryPath("/IL2CPP/__signature_aliases");
    private static final CategoryPath SIGNATURE_OPAQUE =
            new CategoryPath("/IL2CPP/__signature_opaque");
    private static final CategoryPath SIGNATURES = new CategoryPath("/IL2CPP/__signatures");
    private static final Pattern ARRAY_SUFFIX = Pattern.compile("\\[\\s*(\\d+)\\s*]\\s*$");
    private static final Pattern SPACE = Pattern.compile("\\s+");
    private static final String OWNED_DESCRIPTION = "TurboHeader IL2CPP managed type";

    private final Program program;
    private final DataTypeManager dtm;
    private final Model model;
    private final TaskMonitor monitor;
    private final LayoutPolicy layoutPolicy;
    private final Map<String, Structure> structures = new LinkedHashMap<>();
    private final Map<String, DataType> resolvedTypes = new HashMap<>();
    private final Map<String, DataType> opaqueTypes = new HashMap<>();
    private final Map<String, DataType> functionTypes = new HashMap<>();
    private final List<DataType> stagedTypes = new ArrayList<>();
    private int fieldsImported;
    private int importedLegacyUnknown;
    private int importedSidecarCopied;
    private int importedHeaderInferred;
    private int importedAbiDefined;
    private int overlapUnions;
    private int fallbackFields;
    private final List<ImportDiagnostic> diagnostics = new ArrayList<>();

    public GhidraTypeImporter(Program program, Model model, TaskMonitor monitor) {
        this(program, model, monitor, LayoutPolicy.ALLOW_INFERRED);
    }

    public GhidraTypeImporter(Program program, Model model, TaskMonitor monitor,
            LayoutPolicy layoutPolicy) {
        this.program = program;
        this.dtm = program.getDataTypeManager();
        this.model = model;
        this.monitor = monitor == null ? TaskMonitor.DUMMY : monitor;
        this.layoutPolicy = Objects.requireNonNull(layoutPolicy, "layoutPolicy");
    }

    public ImportStats importTypes() throws CancelledException {
        long started = System.nanoTime();
        resetImportState();
        validateModel();
        int transaction = dtm.startTransaction("TurboHeader IL2CPP type import");
        boolean commit = false;
        try {
            monitor.initialize((long) model.structures().size() * 2L);
            monitor.setMessage("Creating IL2CPP type shells");
            createStructureShells();
            monitor.setMessage("Populating IL2CPP type fields");
            populateStructures();
            monitor.checkCancelled();
            monitor.setMessage("Committing IL2CPP data types");
            commitStagedTypes();
            commit = true;
        }
        finally {
            dtm.endTransaction(transaction, commit);
        }
        long elapsed = System.nanoTime() - started;
        return new ImportStats(structures.size(), fieldsImported, overlapUnions,
                fallbackFields, model.missingOffsets(), importedEvidenceCounts(),
                model.lengthEvidenceCounts(),
                List.copyOf(diagnostics), elapsed);
    }

    private void resetImportState() {
        structures.clear();
        resolvedTypes.clear();
        opaqueTypes.clear();
        functionTypes.clear();
        stagedTypes.clear();
        diagnostics.clear();
        fieldsImported = 0;
        importedLegacyUnknown = 0;
        importedSidecarCopied = 0;
        importedHeaderInferred = 0;
        importedAbiDefined = 0;
        overlapUnions = 0;
        fallbackFields = 0;
    }

    private void validateModel() {
        int programPointerSize = program.getDefaultPointerSize();
        if (model.pointerSize() != programPointerSize) {
            throw new IllegalArgumentException("model pointer size " + model.pointerSize() +
                    " does not match program pointer size " + programPointerSize);
        }
        if (layoutPolicy != LayoutPolicy.ALLOW_INFERRED) {
            for (StructDef definition : model.structures()) {
                if (layoutPolicy == LayoutPolicy.REQUIRE_AUTHORITATIVE) {
                    requireAuthoritative(definition.name() + " length",
                            definition.lengthEvidence());
                }
                for (FieldDef field : definition.fields()) {
                    requireExternalOffset(definition.name() + "." + field.name(),
                            field.offsetEvidence());
                }
            }
        }

        Set<String> names = new HashSet<>();
        Map<String, Integer> structureLengths = new HashMap<>();
        for (StructDef definition : model.structures()) {
            structureLengths.put(definition.name(), definition.length());
        }
        for (StructDef definition : model.structures()) {
            if (!names.add(definition.name())) {
                throw new IllegalArgumentException("duplicate structure: " + definition.name());
            }
            Map<String, FieldDef> fieldsByName = new HashMap<>();
            for (FieldDef field : definition.fields()) {
                if (field.offset() >= definition.length()) {
                    throw new IllegalArgumentException("field " + definition.name() + "." +
                            field.name() + " starts outside the structure");
                }
                if (fieldsByName.putIfAbsent(field.name(), field) != null) {
                    throw new IllegalArgumentException("duplicate field " + definition.name() + "." +
                            field.name());
                }
                OptionalInt length = knownTypeLength(field.cType(), structureLengths);
                if (length.isPresent() && (long) field.offset() + length.getAsInt() > definition.length()) {
                    throw new IllegalArgumentException("field " + definition.name() + "." + field.name() +
                            " exceeds the structure length");
                }
            }

            FieldDef klass = fieldsByName.get("klass");
            FieldDef monitorField = fieldsByName.get("monitor");
            if (definition.name().endsWith("_o") && (klass != null || monitorField != null)) {
                if (klass == null || monitorField == null || klass.offset() != 0 ||
                        monitorField.offset() != model.pointerSize() ||
                        !normalizeCType(klass.cType()).endsWith("*") ||
                        !normalizeCType(monitorField.cType()).endsWith("*")) {
                    throw new IllegalArgumentException("invalid object header in " + definition.name());
                }
                int headerSize = 2 * model.pointerSize();
                for (FieldDef field : definition.fields()) {
                    if (field != klass && field != monitorField && field.offset() < headerSize) {
                        throw new IllegalArgumentException("instance field " + definition.name() + "." +
                                field.name() + " overlaps the object header");
                    }
                }
            }
        }
    }

    private static void requireAuthoritative(String subject, LayoutEvidence evidence) {
        if (evidence != LayoutEvidence.SIDECAR_COPIED &&
                evidence != LayoutEvidence.ABI_DEFINED) {
            throw new IllegalArgumentException(subject + " is not authoritative (" + evidence + "). " +
                    "require-authoritative rejects inferred structure extents; use " +
                    "require-external-offsets for normal imports when managed field offsets must be " +
                    "external but some total sizes are unavailable");
        }
    }

    private static void requireExternalOffset(String subject, LayoutEvidence evidence) {
        if (evidence != LayoutEvidence.SIDECAR_COPIED &&
                evidence != LayoutEvidence.ABI_DEFINED) {
            throw new IllegalArgumentException(subject + " has no external field offset (" +
                    evidence + ")");
        }
    }

    private String structureDescription(StructDef definition) {
        int unknown = 0;
        int copied = 0;
        int inferred = 0;
        int abi = 0;
        for (FieldDef field : definition.fields()) {
            switch (field.offsetEvidence()) {
                case LEGACY_UNKNOWN -> unknown++;
                case SIDECAR_COPIED -> copied++;
                case HEADER_INFERRED -> inferred++;
                case ABI_DEFINED -> abi++;
            }
        }
        return String.format(Locale.ROOT,
                "%s; source=%s; extent=%s; offsets copied=%d, inferred=%d, ABI=%d, unknown=%d",
                OWNED_DESCRIPTION, sourceDescription(), evidenceDescription(definition.lengthEvidence()),
                copied, inferred, abi, unknown);
    }

    private String sourceDescription() {
        return switch (model.offsetSource()) {
            case LEGACY_UNKNOWN -> "legacy model (provenance unavailable)";
            case HEADER_ONLY -> "il2cpp.h natural layout (not runtime-authoritative)";
            case TYPE_OFFSETS_JSON -> "type_offsets.json schema " + model.offsetSchemaVersion();
            case DUMP_CS -> "dump.cs legacy sidecar";
        };
    }

    private static String evidenceDescription(LayoutEvidence evidence) {
        return switch (evidence) {
            case LEGACY_UNKNOWN -> "legacy/unknown";
            case SIDECAR_COPIED -> "copied from sidecar";
            case HEADER_INFERRED -> "derived from header layout";
            case ABI_DEFINED -> "defined by IL2CPP ABI";
        };
    }

    private static String evidenceComment(LayoutEvidence evidence) {
        return switch (evidence) {
            case HEADER_INFERRED -> "Offset inferred from natural il2cpp.h layout; not runtime-authoritative";
            case LEGACY_UNKNOWN -> "Offset provenance unavailable (legacy I2GF model)";
            case SIDECAR_COPIED, ABI_DEFINED -> null;
        };
    }

    private static String joinComments(String first, String second) {
        if (first == null || first.isBlank()) {
            return second;
        }
        if (second == null || second.isBlank()) {
            return first;
        }
        return first + "; " + second;
    }

    private void removeOwnedTypes() throws CancelledException {
        List<DataType> owned = new ArrayList<>();
        var all = dtm.getAllDataTypes();
        while (all.hasNext()) {
            monitor.checkCancelled();
            DataType type = all.next();
            if (isOwned(type)) {
                owned.add(type);
            }
        }
        if (!owned.isEmpty()) {
            for (int rank = 0; rank <= 3; rank++) {
                List<DataType> batch = new ArrayList<>();
                for (DataType type : owned) {
                    if (removalRank(type) == rank) {
                        batch.add(type);
                    }
                }
                if (!batch.isEmpty()) {
                    dtm.remove(batch, monitor);
                }
            }
        }

        List<String> remaining = new ArrayList<>();
        var allAfterRemoval = dtm.getAllDataTypes();
        while (allAfterRemoval.hasNext()) {
            monitor.checkCancelled();
            DataType type = allAfterRemoval.next();
            if (isOwned(type)) {
                remaining.add(type.getCategoryPath() + "/" + type.getName());
            }
        }
        if (!remaining.isEmpty()) {
            remaining.sort(Comparator.naturalOrder());
            throw new IllegalStateException("unable to remove stale TurboHeader types: " +
                    String.join(", ", remaining));
        }
    }

    private static int removalRank(DataType type) {
        if (ROOT.equals(type.getCategoryPath())) {
            return 0;
        }
        if (OVERLAPS.equals(type.getCategoryPath())) {
            return type.getName().contains("__at_") ? 2 : 1;
        }
        return 3;
    }

    private static boolean isOwned(DataType type) {
        CategoryPath category = type.getCategoryPath();
        if (SIGNATURE_ALIASES.equals(category) || SIGNATURE_OPAQUE.equals(category) ||
                SIGNATURES.equals(category)) {
            return true;
        }
        String description = type.getDescription();
        if (description != null && description.startsWith(OWNED_DESCRIPTION)) {
            return true;
        }
        // Recognize helpers and structures produced by TurboHeader 1.0.0 so the first
        // import after upgrading does not retain its iteration-derived names.
        if (ROOT.equals(type.getCategoryPath())) {
            return description != null && description.startsWith("Imported by TurboHeader");
        }
        if (OPAQUE.equals(type.getCategoryPath())) {
            return description != null && description.startsWith("Opaque IL2CPP C type");
        }
        if (FUNCTIONS.equals(type.getCategoryPath())) {
            return type.getName().startsWith("__fn_");
        }
        return OVERLAPS.equals(type.getCategoryPath()) && type.getName().startsWith("__overlap_");
    }

    private void createStructureShells() throws CancelledException {
        for (StructDef definition : model.structures()) {
            monitor.checkCancelled();
            StructureDataType shell = new StructureDataType(ROOT, definition.name(),
                    definition.length(), dtm);
            shell.setPackingEnabled(false);
            shell.setDescription(structureDescription(definition));
            structures.put(definition.name(), shell);
            stagedTypes.add(shell);
            monitor.incrementProgress(1);
        }
    }

    private void commitStagedTypes() throws CancelledException {
        removeOwnedTypes();
        // The complete graph has already been populated off-manager. Ghidra can now
        // resolve mutual references and helpers in one bulk operation.
        dtm.addDataTypes(stagedTypes, DataTypeConflictHandler.REPLACE_HANDLER, monitor);
    }

    private void populateStructures() throws CancelledException {
        for (StructDef definition : model.structures()) {
            monitor.checkCancelled();
            Structure target = structures.get(definition.name());
            // REPLACE_HANDLER normally gives a fresh structure. Clearing defensively makes
            // reruns deterministic without changing its exact pre-sized length.
            for (var component : target.getDefinedComponents()) {
                target.clearAtOffset(component.getOffset());
            }
            target.setLength(definition.length());
            target.setPackingEnabled(false);

            List<ResolvedField> fields = new ArrayList<>(definition.fields().size());
            Set<String> usedNames = new HashSet<>();
            for (FieldDef field : definition.fields()) {
                DataType type = resolveType(field.cType());
                int length = safeLength(type);
                String name = uniqueFieldName(sanitizeFieldName(field.name()), usedNames);
                fields.add(new ResolvedField(field.offset(), name, field.cType(), type, length,
                        field.offsetEvidence()));
            }
            fields.sort(Comparator.comparingInt(ResolvedField::offset));
            placeFields(target, definition, fields);
            monitor.incrementProgress(1);
        }
    }

    private void placeFields(Structure target, StructDef definition,
            List<ResolvedField> fields) throws CancelledException {
        int i = 0;
        while (i < fields.size()) {
            monitor.checkCancelled();
            ResolvedField first = fields.get(i);
            long clusterEnd = end(first);
            int j = i + 1;
            while (j < fields.size() && fields.get(j).offset() < clusterEnd) {
                clusterEnd = Math.max(clusterEnd, end(fields.get(j)));
                j++;
            }

            if (j == i + 1) {
                placeOne(target, definition, first);
            }
            else {
                placeOverlap(target, definition, fields.subList(i, j));
            }
            i = j;
        }
    }

    private void placeOne(Structure target, StructDef owner, ResolvedField field) {
        if (!fits(owner, field.offset(), field.length())) {
            placeFallback(target, owner, field, "field exceeds declared structure length");
            return;
        }
        try {
            target.replaceAtOffset(field.offset(), field.dataType(), -1, field.name(),
                    evidenceComment(field.evidence()));
            recordImported(field.evidence());
        }
        catch (IllegalArgumentException e) {
            placeFallback(target, owner, field, e.getMessage());
        }
    }

    private void placeOverlap(Structure target, StructDef owner, List<ResolvedField> cluster) {
        int start = cluster.stream().mapToInt(ResolvedField::offset).min().orElseThrow();
        int end = cluster.stream().mapToInt(f -> saturatedEnd(f.offset(), f.length())).max().orElse(start + 1);
        if (start >= owner.length() || end > owner.length()) {
            for (ResolvedField field : cluster) {
                placeFallback(target, owner, field, "overlap cluster exceeds structure length");
            }
            return;
        }

        String unionName = "__overlap_" + sanitizeTypeName(owner.name()) + "_" +
                Integer.toHexString(start) + "_" + structuralId(cluster);
        UnionDataType unionCandidate = new UnionDataType(OVERLAPS, unionName, dtm);
        unionCandidate.setPackingEnabled(false);
        unionCandidate.setDescription(OWNED_DESCRIPTION + "; overlap helper");
        Set<String> unionNames = new HashSet<>();

        try {
            for (ResolvedField field : cluster) {
                String memberName = uniqueFieldName(field.name(), unionNames);
                int delta = field.offset() - start;
                if (delta == 0) {
                    unionCandidate.add(field.dataType(), -1, memberName,
                            evidenceComment(field.evidence()));
                }
                else {
                    int wrapperLength = delta + field.length();
                    String wrapperName = unionName + "__at_" + Integer.toHexString(delta) + "_" +
                            structuralId(List.of(field));
                    StructureDataType wrapper = new StructureDataType(OVERLAPS, wrapperName,
                            wrapperLength, dtm);
                    wrapper.setPackingEnabled(false);
                    wrapper.setDescription(OWNED_DESCRIPTION + "; shifted overlap helper");
                    wrapper.replaceAtOffset(delta, field.dataType(), -1, memberName,
                            joinComments("Original offset +0x" + Integer.toHexString(delta),
                                    evidenceComment(field.evidence())));
                    stagedTypes.add(wrapper);
                    unionCandidate.add(wrapper, -1, memberName + "__view", null);
                }
            }
            stagedTypes.add(unionCandidate);
            target.replaceAtOffset(start, unionCandidate, -1,
                    "__overlap_0x" + Integer.toHexString(start),
                    "Explicit-layout overlap; expand the union to view all fields");
            overlapUnions++;
            for (ResolvedField field : cluster) {
                recordImported(field.evidence());
            }
        }
        catch (IllegalArgumentException e) {
            stagedTypes.removeIf(type -> OVERLAPS.equals(type.getCategoryPath()) &&
                    (type.getName().equals(unionName) || type.getName().startsWith(unionName + "__at_")));
            // Preserve at least one field and report all others as byte-range fallbacks.
            boolean first = true;
            for (ResolvedField field : cluster) {
                if (first) {
                    placeOne(target, owner, field);
                    first = false;
                }
                else {
                    fallbackFields++;
                    diagnostics.add(new ImportDiagnostic(owner.name(), field.name(), field.offset(),
                            "overlap helper placement failed: " + message(e)));
                }
            }
        }
    }

    private void placeFallback(Structure target, StructDef owner, ResolvedField field, String reason) {
        int remaining = owner.length() - field.offset();
        if (remaining <= 0) {
            fallbackFields++;
            diagnostics.add(new ImportDiagnostic(owner.name(), field.name(), field.offset(), reason));
            return;
        }
        int length = Math.max(1, Math.min(field.length(), remaining));
        DataType bytes = new ArrayDataType(
                AbstractIntegerDataType.getUnsignedDataType(1, dtm), length, 1, dtm);
        try {
            target.replaceAtOffset(field.offset(), bytes, -1, field.name(),
                    "TurboHeader fallback for '" + field.originalType() + "': " + reason);
            recordImported(field.evidence());
        }
        catch (IllegalArgumentException ignored) {
            // A previous overlapping fallback may occupy this range.
        }
        fallbackFields++;
        diagnostics.add(new ImportDiagnostic(owner.name(), field.name(), field.offset(), reason));
    }

    private DataType resolveType(String original) {
        DataType resolved = resolvedTypes.get(original);
        if (resolved == null) {
            resolved = resolveTypeUncached(original);
            resolvedTypes.put(original, resolved);
        }
        return resolved;
    }

    private void recordImported(LayoutEvidence evidence) {
        fieldsImported++;
        switch (evidence) {
            case LEGACY_UNKNOWN -> importedLegacyUnknown++;
            case SIDECAR_COPIED -> importedSidecarCopied++;
            case HEADER_INFERRED -> importedHeaderInferred++;
            case ABI_DEFINED -> importedAbiDefined++;
        }
    }

    private TypeModel.EvidenceCounts importedEvidenceCounts() {
        return new TypeModel.EvidenceCounts(importedLegacyUnknown, importedSidecarCopied,
                importedHeaderInferred, importedAbiDefined);
    }

    private DataType resolveTypeUncached(String original) {
        String text = normalizeCType(original);
        List<Integer> dimensions = new ArrayList<>();
        Matcher arrayMatcher = ARRAY_SUFFIX.matcher(text);
        while (arrayMatcher.find()) {
            try {
                dimensions.add(Integer.parseUnsignedInt(arrayMatcher.group(1)));
            }
            catch (NumberFormatException e) {
                dimensions.add(1);
            }
            text = text.substring(0, arrayMatcher.start()).trim();
            arrayMatcher = ARRAY_SUFFIX.matcher(text);
        }

        DataType functionPointer = functionTypes.get(text);
        if (functionPointer == null) {
            functionPointer = createFunctionPointer(text);
            if (functionPointer != null) {
                functionTypes.put(text, functionPointer);
            }
        }
        if (functionPointer != null) {
            DataType type = functionPointer;
            for (int i = dimensions.size() - 1; i >= 0; i--) {
                type = new ArrayDataType(type, dimensions.get(i), -1, dtm);
            }
            return type;
        }

        int pointers = 0;
        while (text.endsWith("*")) {
            pointers++;
            text = text.substring(0, text.length() - 1).trim();
        }
        String baseName = stripTag(text);
        DataType type = resolveBase(baseName);
        for (int i = 0; i < pointers; i++) {
            type = dtm.getPointer(type, model.pointerSize());
        }
        for (int i = dimensions.size() - 1; i >= 0; i--) {
            int count = dimensions.get(i);
            if (count > 0) {
                type = new ArrayDataType(type, count, -1, dtm);
            }
        }
        return type;
    }

    private DataType createFunctionPointer(String declaration) {
        int marker = declaration.indexOf("(*)");
        if (marker < 1) {
            return null;
        }
        int argumentsStart = marker + 3;
        if (argumentsStart >= declaration.length() || declaration.charAt(argumentsStart) != '(' ||
                declaration.charAt(declaration.length() - 1) != ')') {
            return null;
        }

        String returnText = declaration.substring(0, marker).trim();
        String argumentsText = declaration.substring(argumentsStart + 1,
                declaration.length() - 1).trim();
        FunctionDefinitionDataType function = new FunctionDefinitionDataType(FUNCTIONS,
                "__fn_" + shortHash(declaration), dtm);
        function.setReturnType(resolveType(returnText));
        function.setComment(OWNED_DESCRIPTION + "; function pointer " + declaration);

        List<ParameterDefinition> parameters = new ArrayList<>();
        if (!argumentsText.isEmpty() && !argumentsText.equals("void")) {
            int index = 0;
            for (String argument : splitArguments(argumentsText)) {
                if (argument.equals("...")) {
                    function.setVarArgs(true);
                    continue;
                }
                parameters.add(new ParameterDefinitionImpl("arg" + index++, resolveType(argument), null));
            }
        }
        function.setArguments(parameters.toArray(ParameterDefinition[]::new));
        stagedTypes.add(function);
        return dtm.getPointer(function, model.pointerSize());
    }

    private static List<String> splitArguments(String text) {
        List<String> result = new ArrayList<>();
        int parentheses = 0;
        int brackets = 0;
        int start = 0;
        for (int i = 0; i < text.length(); i++) {
            switch (text.charAt(i)) {
                case '(' -> parentheses++;
                case ')' -> parentheses--;
                case '[' -> brackets++;
                case ']' -> brackets--;
                case ',' -> {
                    if (parentheses == 0 && brackets == 0) {
                        result.add(text.substring(start, i).trim());
                        start = i + 1;
                    }
                }
                default -> {
                }
            }
        }
        result.add(text.substring(start).trim());
        return result;
    }

    private DataType resolveBase(String name) {
        Structure known = structures.get(name);
        if (known != null) {
            return known;
        }

        DataType abiType = resolveAbiType(name);
        if (abiType != null) {
            return abiType;
        }

        String key = name.toLowerCase(Locale.ROOT);
        return switch (key) {
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
            case "intptr_t", "ssize_t", "ptrdiff_t" -> signed(model.pointerSize());
            case "uintptr_t", "size_t" -> unsigned(model.pointerSize());
            case "long", "long int", "signed long", "signed long int" -> signed(model.pointerSize());
            case "unsigned long", "unsigned long int" -> unsigned(model.pointerSize());
            case "float" -> FloatDataType.dataType;
            case "double" -> DoubleDataType.dataType;
            case "wchar_t" -> unsigned(2);
            default -> opaqueTypes.computeIfAbsent(name, this::createOpaqueType);
        };
    }

    private DataType resolveAbiType(String name) {
        return switch (name) {
            case "il2cpp_array_size_t" -> unsigned(model.pointerSize());
            case "il2cpp_array_lower_bound_t" -> signed(4);
            case "Il2CppMethodPointer" -> dtm.getPointer(VoidDataType.dataType, model.pointerSize());
            case "InvokerMethod" -> abiFunctionPointer("InvokerMethod", "void", List.of(
                    "Il2CppMethodPointer", "MethodInfo*", "void*", "void**", "void*"));
            default -> null;
        };
    }

    private DataType abiFunctionPointer(String name, String returnType,
            List<String> parameterTypes) {
        String key = "abi:" + name;
        DataType existing = functionTypes.get(key);
        if (existing != null) {
            return existing;
        }

        FunctionDefinitionDataType function = new FunctionDefinitionDataType(
                FUNCTIONS, "__abi_" + name, dtm);
        DataType pointer = dtm.getPointer(function, model.pointerSize());
        functionTypes.put(key, pointer);
        function.setReturnType(resolveType(returnType));
        List<ParameterDefinition> arguments = new ArrayList<>(parameterTypes.size());
        for (int index = 0; index < parameterTypes.size(); index++) {
            arguments.add(new ParameterDefinitionImpl("arg" + index,
                    resolveType(parameterTypes.get(index)), null));
        }
        function.setArguments(arguments.toArray(ParameterDefinition[]::new));
        function.setComment(OWNED_DESCRIPTION + "; IL2CPP ABI function pointer " + name);
        stagedTypes.add(function);
        return pointer;
    }

    private DataType createOpaqueType(String rawName) {
        String name = sanitizeTypeName(rawName);
        DataType existing = dtm.getDataType(new DataTypePath(OPAQUE, name));
        if (existing != null && !isOwned(existing)) {
            return existing;
        }
        StructureDataType opaque = new StructureDataType(OPAQUE, name,
                model.pointerSize(), dtm);
        opaque.setPackingEnabled(false);
        opaque.setDescription(OWNED_DESCRIPTION + "; opaque C type, size assumed by native parser");
        stagedTypes.add(opaque);
        return opaque;
    }

    private DataType signed(int bytes) {
        return AbstractIntegerDataType.getSignedDataType(bytes, dtm);
    }

    private DataType unsigned(int bytes) {
        return AbstractIntegerDataType.getUnsignedDataType(bytes, dtm);
    }

    private static String normalizeCType(String type) {
        String text = type.trim()
                .replaceAll("\\b(const|volatile|restrict|__restrict|__restrict__)\\b", " ")
                .replaceAll("\\b(__cdecl|__stdcall|__fastcall|__thiscall)\\b", " ");
        return SPACE.matcher(text).replaceAll(" ").trim();
    }

    private OptionalInt knownTypeLength(String original, Map<String, Integer> structureLengths) {
        String text = normalizeCType(original);
        long multiplier = 1;
        Matcher arrayMatcher = ARRAY_SUFFIX.matcher(text);
        while (arrayMatcher.find()) {
            int count;
            try {
                count = Integer.parseUnsignedInt(arrayMatcher.group(1));
            }
            catch (NumberFormatException e) {
                throw new IllegalArgumentException("invalid array bound in type: " + original, e);
            }
            if (count == 0 || multiplier > Integer.MAX_VALUE / (long) count) {
                throw new IllegalArgumentException("invalid array size in type: " + original);
            }
            multiplier *= count;
            text = text.substring(0, arrayMatcher.start()).trim();
            arrayMatcher = ARRAY_SUFFIX.matcher(text);
        }

        if (text.contains("(*)")) {
            long length = (long) model.pointerSize() * multiplier;
            if (length > Integer.MAX_VALUE) {
                throw new IllegalArgumentException("type is too large: " + original);
            }
            return OptionalInt.of((int) length);
        }

        int pointers = 0;
        while (text.endsWith("*")) {
            pointers++;
            text = text.substring(0, text.length() - 1).trim();
        }

        Integer baseLength;
        if (pointers > 0) {
            baseLength = model.pointerSize();
        }
        else {
            String baseName = stripTag(text);
            baseLength = knownScalarLength(baseName, structureLengths);
        }
        if (baseLength == null) {
            return OptionalInt.empty();
        }
        long length = baseLength * multiplier;
        if (length > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("type is too large: " + original);
        }
        return OptionalInt.of((int) length);
    }

    private Integer knownScalarLength(String name, Map<String, Integer> structureLengths) {
        Integer structureLength = structureLengths.get(name);
        if (structureLength != null) {
            return structureLength;
        }
        return switch (name.toLowerCase(Locale.ROOT)) {
            case "bool", "_bool", "char", "signed char", "int8_t", "sbyte",
                    "unsigned char", "uint8_t", "byte" -> 1;
            case "short", "short int", "signed short", "signed short int", "int16_t",
                    "unsigned short", "unsigned short int", "uint16_t", "il2cppchar",
                    "wchar_t" -> 2;
            case "int", "signed", "signed int", "int32_t", "unsigned", "unsigned int",
                    "uint32_t", "float" -> 4;
            case "long long", "long long int", "signed long long", "int64_t",
                    "unsigned long long", "unsigned long long int", "uint64_t", "double" -> 8;
            case "intptr_t", "ssize_t", "ptrdiff_t", "uintptr_t", "size_t", "long",
                    "long int", "signed long", "signed long int", "unsigned long",
                    "unsigned long int", "il2cpp_array_size_t", "Il2CppMethodPointer",
                    "InvokerMethod" -> model.pointerSize();
            case "il2cpp_array_lower_bound_t" -> 4;
            default -> null;
        };
    }

    private static String stripTag(String text) {
        if (text.startsWith("struct ")) {
            return text.substring(7).trim();
        }
        if (text.startsWith("union ")) {
            return text.substring(6).trim();
        }
        if (text.startsWith("enum ")) {
            return text.substring(5).trim();
        }
        return text;
    }

    private static int safeLength(DataType type) {
        int length = type.getLength();
        return length > 0 ? length : 1;
    }

    private static boolean fits(StructDef owner, int offset, int length) {
        return offset >= 0 && length > 0 && (long) offset + length <= owner.length();
    }

    private static long end(ResolvedField field) {
        return (long) field.offset() + Math.max(1, field.length());
    }

    private static int saturatedEnd(int offset, int length) {
        long end = (long) offset + Math.max(1, length);
        return end > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) end;
    }

    private static String sanitizeFieldName(String name) {
        String clean = name.replaceAll("[^A-Za-z0-9_$]", "_");
        if (clean.isBlank()) {
            return "field";
        }
        if (Character.isDigit(clean.charAt(0))) {
            return "_" + clean;
        }
        return clean;
    }

    private static String sanitizeTypeName(String name) {
        String clean = name.replaceAll("[^A-Za-z0-9_.$]", "_");
        if (clean.isBlank()) {
            return "anonymous";
        }
        return clean;
    }

    private static String uniqueFieldName(String base, Set<String> used) {
        if (used.add(base)) {
            return base;
        }
        for (int i = 2; ; i++) {
            String candidate = base + "__" + i;
            if (used.add(candidate)) {
                return candidate;
            }
        }
    }

    private static String structuralId(List<ResolvedField> fields) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            List<ResolvedField> canonical = new ArrayList<>(fields);
            canonical.sort(Comparator.comparingInt(ResolvedField::offset)
                    .thenComparing(ResolvedField::name)
                    .thenComparing(ResolvedField::originalType)
                    .thenComparingInt(ResolvedField::length));
            for (ResolvedField field : canonical) {
                digest.update(Integer.toString(field.offset()).getBytes(StandardCharsets.UTF_8));
                digest.update((byte) 0);
                digest.update(field.name().getBytes(StandardCharsets.UTF_8));
                digest.update((byte) 0);
                digest.update(field.originalType().getBytes(StandardCharsets.UTF_8));
                digest.update((byte) 0);
                digest.update(Integer.toString(field.length()).getBytes(StandardCharsets.UTF_8));
                digest.update((byte) 0xff);
            }
            byte[] value = digest.digest();
            StringBuilder result = new StringBuilder(12);
            for (int i = 0; i < 6; i++) {
                result.append(String.format(Locale.ROOT, "%02x", value[i]));
            }
            return result.toString();
        }
        catch (NoSuchAlgorithmException e) {
            throw new AssertionError("SHA-256 is required by the Java runtime", e);
        }
    }

    private static String shortHash(String text) {
        try {
            byte[] value = MessageDigest.getInstance("SHA-256")
                    .digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(12);
            for (int i = 0; i < 6; i++) {
                result.append(String.format(Locale.ROOT, "%02x", value[i]));
            }
            return result.toString();
        }
        catch (NoSuchAlgorithmException e) {
            throw new AssertionError("SHA-256 is required by the Java runtime", e);
        }
    }

    private static String message(IllegalArgumentException error) {
        return error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage();
    }

    private record ResolvedField(int offset, String name, String originalType,
            DataType dataType, int length, LayoutEvidence evidence) {
    }

    public record ImportDiagnostic(String structure, String field, int offset, String reason) {
    }

    public record ImportStats(int structures, int fields, int overlapUnions,
            int fallbackFields, int missingOffsets, TypeModel.EvidenceCounts evidenceCounts,
            TypeModel.EvidenceCounts lengthEvidenceCounts,
            List<ImportDiagnostic> diagnostics,
            long elapsedNanos) {
        public double elapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }

    public enum LayoutPolicy {
        ALLOW_INFERRED,
        REQUIRE_EXTERNAL_OFFSETS,
        REQUIRE_AUTHORITATIVE
    }
}
