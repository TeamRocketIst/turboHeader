package turboheader.il2cpp;

import static turboheader.il2cpp.TypeModel.FieldDef;
import static turboheader.il2cpp.TypeModel.Model;
import static turboheader.il2cpp.TypeModel.StructDef;

import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public final class GhidraImporterIntegrityTest {
    public static void main(String[] args) throws Exception {
        rejectsPointerMismatchBeforeTransaction();
        rejectsInvalidObjectHeaderBeforeTransaction();
        acceptsKlassMemberInRuntimeStructure();
        rejectsDuplicateFieldsAndKnownOutOfBoundsTypes();
        strictPolicyRejectsInferredLayoutsBeforeTransaction();
        reimportsWithoutGrowthAndRemovesStaleOwnedTypes();
        cancellationRollsBackCleanupAndShellCreation();
        reportsFallbackReasons();
        importsFunctionPointersAsCodePointers();
        importsIl2CppAbiCallbackTypes();
        System.out.println("Ghidra importer integrity tests passed");
    }

    private static void strictPolicyRejectsInferredLayoutsBeforeTransaction() throws Exception {
        var inferred = TypeModel.LayoutEvidence.HEADER_INFERRED;
        Model headerOnly = new Model(8, 0, List.of(new StructDef("Inferred", 4,
                List.of(new FieldDef(0, "value", "int32_t", inferred)), inferred)),
                TypeModel.OffsetSource.HEADER_ONLY, 0);
        Program rejectedProgram = new Program();
        expectIllegalArgument(() -> new GhidraTypeImporter(rejectedProgram, headerOnly,
                TaskMonitor.DUMMY, GhidraTypeImporter.LayoutPolicy.REQUIRE_AUTHORITATIVE)
                .importTypes(), "inferred strict layout");
        check(rejectedProgram.getDataTypeManager().getTransactionCount() == 0,
                "strict provenance rejection opened a transaction");
        Program rejectedExternalProgram = new Program();
        expectIllegalArgument(() -> new GhidraTypeImporter(rejectedExternalProgram, headerOnly,
                TaskMonitor.DUMMY, GhidraTypeImporter.LayoutPolicy.REQUIRE_EXTERNAL_OFFSETS)
                .importTypes(), "inferred external-offset layout");
        check(rejectedExternalProgram.getDataTypeManager().getTransactionCount() == 0,
                "external-offset rejection opened a transaction");

        var copied = TypeModel.LayoutEvidence.SIDECAR_COPIED;
        Model schemaTwo = new Model(8, 0, List.of(new StructDef("SchemaTwo", 4,
                List.of(new FieldDef(0, "value", "int32_t", copied)), inferred)),
                TypeModel.OffsetSource.TYPE_OFFSETS_JSON, 2);
        Program externalProgram = new Program();
        new GhidraTypeImporter(externalProgram, schemaTwo, TaskMonitor.DUMMY,
                GhidraTypeImporter.LayoutPolicy.REQUIRE_EXTERNAL_OFFSETS).importTypes();
        check(externalProgram.getDataTypeManager().getDataType(
                new DataTypePath(GhidraTypeImporter.ROOT, "SchemaTwo")) != null,
                "external field offsets with inferred extent were not imported");
        Program strictSchemaTwoProgram = new Program();
        expectIllegalArgumentContaining(() -> new GhidraTypeImporter(strictSchemaTwoProgram, schemaTwo,
                TaskMonitor.DUMMY, GhidraTypeImporter.LayoutPolicy.REQUIRE_AUTHORITATIVE)
                .importTypes(), "schema-two inferred extent", "use require-external-offsets");

        Model exact = new Model(8, 0, List.of(new StructDef("Exact", 4,
                List.of(new FieldDef(0, "value", "int32_t", copied)), copied)),
                TypeModel.OffsetSource.TYPE_OFFSETS_JSON, 3);
        Program acceptedProgram = new Program();
        new GhidraTypeImporter(acceptedProgram, exact, TaskMonitor.DUMMY,
                GhidraTypeImporter.LayoutPolicy.REQUIRE_AUTHORITATIVE).importTypes();
        check(acceptedProgram.getDataTypeManager().getDataType(
                new DataTypePath(GhidraTypeImporter.ROOT, "Exact")) != null,
                "authoritative strict layout was not imported");
    }

    private static void rejectsPointerMismatchBeforeTransaction() throws Exception {
        Program program = new Program(4);
        expectIllegalArgument(() -> importer(program, overlapModel()).importTypes(),
                "pointer size mismatch");
        check(program.getDataTypeManager().getTransactionCount() == 0,
                "pointer mismatch opened a transaction");
    }

    private static void rejectsInvalidObjectHeaderBeforeTransaction() throws Exception {
        Model invalid = new Model(8, 0, List.of(new StructDef("Broken_o", 32, List.of(
                new FieldDef(0, "klass", "void *"),
                new FieldDef(8, "monitor", "void *"),
                new FieldDef(8, "fields", "int32_t")))));
        Program program = new Program();
        expectIllegalArgument(() -> importer(program, invalid).importTypes(), "object header overlap");
        check(program.getDataTypeManager().getTransactionCount() == 0,
                "invalid header opened a transaction");
    }

    private static void acceptsKlassMemberInRuntimeStructure() throws Exception {
        Model runtime = new Model(8, 0, List.of(new StructDef("RuntimeClass", 16,
                List.of(new FieldDef(8, "klass", "void *")))));
        Program program = new Program();
        importer(program, runtime).importTypes();
        check(program.getDataTypeManager().getDataType(
                new DataTypePath(GhidraTypeImporter.ROOT, "RuntimeClass")) != null,
                "runtime structure with klass member was rejected");
    }

    private static void rejectsDuplicateFieldsAndKnownOutOfBoundsTypes() throws Exception {
        Model duplicate = new Model(8, 0, List.of(new StructDef("Duplicate", 8, List.of(
                new FieldDef(0, "value", "int32_t"),
                new FieldDef(4, "value", "int32_t")))));
        Program duplicateProgram = new Program();
        expectIllegalArgument(() -> importer(duplicateProgram, duplicate).importTypes(),
                "duplicate field");
        check(duplicateProgram.getDataTypeManager().getTransactionCount() == 0,
                "duplicate field opened a transaction");

        Model outOfBounds = new Model(8, 0, List.of(new StructDef("TooShort", 8,
                List.of(new FieldDef(4, "wide", "int64_t")))));
        Program boundsProgram = new Program();
        expectIllegalArgument(() -> importer(boundsProgram, outOfBounds).importTypes(),
                "known out-of-bounds field");
        check(boundsProgram.getDataTypeManager().getTransactionCount() == 0,
                "known out-of-bounds field opened a transaction");
    }

    private static void reimportsWithoutGrowthAndRemovesStaleOwnedTypes() throws Exception {
        Program program = new Program();
        StructureDataType userType = new StructureDataType(GhidraTypeImporter.ROOT,
                "UserType", 4, program.getDataTypeManager());
        userType.setDescription("created by user");
        program.getDataTypeManager().addDataType(userType, DataTypeConflictHandler.KEEP_HANDLER);
        StructureDataType staleHelper = new StructureDataType(
                new CategoryPath("/IL2CPP/__overlaps"), "__overlap_legacy__at_4", 8,
                program.getDataTypeManager());
        staleHelper.setDescription("TurboHeader IL2CPP managed type; shifted overlap helper");
        program.getDataTypeManager().addDataType(staleHelper,
                DataTypeConflictHandler.KEEP_HANDLER);

        GhidraTypeImporter reusableImporter = importer(program, overlapModel());
        GhidraTypeImporter.ImportStats first = reusableImporter.importTypes();
        Set<String> firstInventory = inventory(program);
        check(first.overlapUnions() == 1, "first overlap import");

        GhidraTypeImporter.ImportStats second = reusableImporter.importTypes();
        Set<String> secondInventory = inventory(program);
        check(firstInventory.equals(secondInventory), "identical reimport changed type inventory");
        check(second.overlapUnions() == 1, "second overlap import");
        check(secondInventory.stream().noneMatch(name -> name.contains(".conflict")),
                "conflict datatype created");

        importer(program, valueModel()).importTypes();
        Set<String> subsetInventory = inventory(program);
        check(subsetInventory.contains("/IL2CPP/UserType"), "unrelated user type removed");
        check(subsetInventory.contains("/IL2CPP/Value"), "replacement model missing");
        check(!subsetInventory.contains("/IL2CPP/Ref_o"), "stale owned structure retained");
        check(subsetInventory.stream().noneMatch(name -> name.startsWith("/IL2CPP/__overlaps/")),
                "stale overlap helper retained");
    }

    private static void cancellationRollsBackCleanupAndShellCreation() throws Exception {
        Program program = new Program();
        importer(program, overlapModel()).importTypes();
        Set<String> before = inventory(program);

        TaskMonitor cancelDuringImport = new TaskMonitor() {
            private int checks;

            @Override
            public void checkCancelled() throws CancelledException {
                if (++checks == 6) {
                    throw new CancelledException();
                }
            }
        };
        try {
            new GhidraTypeImporter(program, valueModel(), cancelDuringImport).importTypes();
            throw new AssertionError("cancellation was ignored");
        }
        catch (CancelledException expected) {
            check(before.equals(inventory(program)), "cancellation did not roll back datatype inventory");
        }
    }

    private static void reportsFallbackReasons() throws Exception {
        Model model = new Model(8, 0, List.of(new StructDef("TailValue", 8,
                List.of(new FieldDef(7, "tail", "unknown_opaque_t")))));
        GhidraTypeImporter.ImportStats stats = importer(new Program(), model).importTypes();
        check(stats.fallbackFields() == 1, "fallback count");
        check(stats.diagnostics().size() == 1, "fallback diagnostic count");
        check(stats.diagnostics().get(0).reason().contains("exceeds"), "fallback reason");
    }

    private static void importsFunctionPointersAsCodePointers() throws Exception {
        Program program = new Program();
        Model model = new Model(8, 0, List.of(new StructDef("Callbacks", 16, List.of(
                new FieldDef(0, "callback", "void (*)(int32_t, void *)"),
                new FieldDef(8, "compare", "int32_t (*)(uint8_t)")))));
        importer(program, model).importTypes();
        Structure callbacks = (Structure) program.getDataTypeManager().getDataType(
                new DataTypePath(GhidraTypeImporter.ROOT, "Callbacks"));
        check(callbacks != null, "callback structure missing");
        for (var component : callbacks.getDefinedComponents()) {
            check(component.getDataType() instanceof PointerDataType, "callback is not a pointer");
            DataType target = ((PointerDataType) component.getDataType()).getDataType();
            check(target instanceof FunctionDefinitionDataType, "callback is not a function definition");
            FunctionDefinitionDataType function = (FunctionDefinitionDataType) target;
            check(function.getArguments().length > 0, "function arguments were dropped");
        }
    }

    private static void importsIl2CppAbiCallbackTypes() throws Exception {
        assertIl2CppAbiCallbackTypes(4);
        assertIl2CppAbiCallbackTypes(8);
    }

    private static void assertIl2CppAbiCallbackTypes(int pointerSize) throws Exception {
        Program program = new Program(pointerSize);
        Model model = new Model(pointerSize, 0,
                List.of(new StructDef("RuntimeAbi", pointerSize * 4, List.of(
                new FieldDef(0, "length", "il2cpp_array_size_t"),
                new FieldDef(pointerSize, "lower", "il2cpp_array_lower_bound_t"),
                new FieldDef(pointerSize * 2, "method", "Il2CppMethodPointer"),
                new FieldDef(pointerSize * 3, "invoker", "InvokerMethod")))));
        importer(program, model).importTypes();
        Structure runtime = (Structure) program.getDataTypeManager().getDataType(
                new DataTypePath(GhidraTypeImporter.ROOT, "RuntimeAbi"));
        check(runtime != null, "runtime ABI structure missing");
        var components = runtime.getDefinedComponents();
        check(components.length == 4, "runtime ABI field count");
        check(components[0].getDataType().getLength() == pointerSize, "array size width");
        check(components[1].getDataType().getLength() == 4, "array lower-bound width");
        check(components[2].getDataType() instanceof PointerDataType,
                "method pointer is not pointer-sized");
        check(components[2].getDataType().getLength() == pointerSize, "method pointer width");
        DataType methodTarget = ((PointerDataType) components[2].getDataType()).getDataType();
        check(!(methodTarget instanceof FunctionDefinitionDataType),
                "method pointer has a global function definition");
        check(methodTarget.getName().equals("void"), "method pointer target is not void");
        check(components[3].getDataType() instanceof PointerDataType,
                "invoker is not a pointer");
        check(components[3].getDataType().getLength() == pointerSize, "invoker width");
        DataType invokerTarget = ((PointerDataType) components[3].getDataType()).getDataType();
        check(invokerTarget instanceof FunctionDefinitionDataType,
                "invoker target is not a function definition");
        FunctionDefinitionDataType invoker = (FunctionDefinitionDataType) invokerTarget;
        check(invoker.getArguments().length == 5, "invoker argument count");
        check(invoker.getArguments()[0].getDataType() instanceof PointerDataType,
                "invoker method-pointer argument is not pointer-sized");
        check(program.getDataTypeManager().getDataType(new DataTypePath(
                new CategoryPath("/IL2CPP/__opaque"), "il2cpp_array_size_t")) == null,
                "array size imported as opaque");
    }

    private static Model overlapModel() {
        return new Model(8, 0, List.of(new StructDef("Ref_o", 32, List.of(
                new FieldDef(0, "klass", "void *"),
                new FieldDef(8, "monitor", "void *"),
                new FieldDef(16, "integerView", "int32_t"),
                new FieldDef(16, "floatView", "float"),
                new FieldDef(24, "next", "void *")))));
    }

    private static Model valueModel() {
        return new Model(8, 0, List.of(new StructDef("Value", 8,
                List.of(new FieldDef(0, "value", "int64_t")))));
    }

    private static GhidraTypeImporter importer(Program program, Model model) {
        return new GhidraTypeImporter(program, model, TaskMonitor.DUMMY);
    }

    private static Set<String> inventory(Program program) {
        Set<String> result = new TreeSet<>();
        var types = program.getDataTypeManager().getAllDataTypes();
        while (types.hasNext()) {
            DataType type = types.next();
            result.add(type.getCategoryPath() + "/" + type.getName());
        }
        return result;
    }

    private static void expectIllegalArgument(ThrowingRunnable action, String label) throws Exception {
        try {
            action.run();
            throw new AssertionError(label + " was accepted");
        }
        catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private static void expectIllegalArgumentContaining(ThrowingRunnable action, String label,
            String expectedText) throws Exception {
        try {
            action.run();
            throw new AssertionError(label + " was accepted");
        }
        catch (IllegalArgumentException expected) {
            check(expected.getMessage().contains(expectedText),
                    label + " did not explain the supported fallback policy");
        }
    }

    private static void check(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
