// Exercises rerun, stale cleanup, validation and rollback in a real Ghidra database.
// @category Data Types

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;
import turboheader.il2cpp.GhidraTypeImporter;
import turboheader.il2cpp.NativeParser;
import turboheader.il2cpp.TypeModel.FieldDef;
import turboheader.il2cpp.TypeModel.Model;
import turboheader.il2cpp.TypeModel.StructDef;

public class VerifyTurboHeaderTransactions extends GhidraScript {
    private static final CategoryPath ROOT = new CategoryPath("/IL2CPP");

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        require(args.length == 3, "expected: il2cpp.h offsets pointer-size");
        int pointerSize = Integer.parseInt(args[2]);
        Model full = NativeParser.parse(Path.of(args[0]), Path.of(args[1]), pointerSize);

        importModel(full, monitor);
        List<String> first = snapshot();
        importModel(full, monitor);
        require(first.equals(snapshot()), "reimport changed the logical datatype snapshot");
        require(first.stream().noneMatch(s -> s.contains(".conflict")), "conflict datatype created");

        addUserType();
        StructDef base = full.structures().stream()
                .filter(s -> s.name().equals("Base_o"))
                .findFirst().orElseThrow();
        Model subset = new Model(pointerSize, 0, List.of(base), full.offsetSource(),
                full.offsetSchemaVersion());
        importModel(subset, monitor);
        List<String> subsetSnapshot = snapshot();
        require(hasType("Base_o"), "subset type is missing");
        require(!hasType("Derived_o"), "stale full-model type survived subset import");
        require(hasType("UserKeep"), "unrelated user type was removed");

        try {
            importModel(full, new PopulationCancelMonitor());
            throw new AssertionError("population cancellation did not abort the import");
        }
        catch (CancelledException expected) {
            List<String> afterCancellation = snapshot();
            if (!subsetSnapshot.equals(afterCancellation)) {
                printerr("before cancellation: " + subsetSnapshot);
                printerr("after cancellation:  " + afterCancellation);
            }
            require(subsetSnapshot.equals(afterCancellation),
                    "cancelled transaction did not restore the datatype snapshot");
        }

        Model mismatch = new Model(pointerSize == 8 ? 4 : 8, 0, subset.structures(),
                subset.offsetSource(), subset.offsetSchemaVersion());
        expectValidationFailure(mismatch, subsetSnapshot, "pointer-size mismatch");

        StructDef invalidHeader = new StructDef("Invalid_o", pointerSize * 2,
                List.of(new FieldDef(0, "klass", "struct Invalid_c *"),
                        new FieldDef(pointerSize, "monitor", "void *"),
                        new FieldDef(pointerSize, "insideHeader", "int32_t")));
        expectValidationFailure(new Model(pointerSize, 0, List.of(invalidHeader)), subsetSnapshot,
                "object-header collision");

        StructDef callbackHolder = new StructDef("CallbackHolder", pointerSize,
                List.of(new FieldDef(0, "callback", "void (*)(int32_t, void *)")));
        importModel(new Model(pointerSize, 0, List.of(callbackHolder)), monitor);
        Structure callbackType = (Structure) currentProgram.getDataTypeManager().getDataType(
                new DataTypePath(ROOT, "CallbackHolder"));
        DataType callback = callbackType.getDefinedComponents()[0].getDataType();
        require(callback instanceof Pointer, "function field is not a pointer");
        DataType signature = ((Pointer) callback).getDataType();
        require(signature instanceof FunctionDefinition, "function field is not a code pointer");
        require(((FunctionDefinition) signature).getArguments().length == 2,
                "function pointer arguments were dropped");

        println("TurboHeader real-Ghidra transaction tests passed");
    }

    private void importModel(Model model, ghidra.util.task.TaskMonitor taskMonitor)
            throws CancelledException {
        new GhidraTypeImporter(currentProgram, model, taskMonitor).importTypes();
    }

    private void expectValidationFailure(Model model, List<String> expected, String label)
            throws CancelledException {
        try {
            importModel(model, monitor);
            throw new AssertionError(label + " was accepted");
        }
        catch (IllegalArgumentException expectedFailure) {
            require(expected.equals(snapshot()), label + " changed the datatype snapshot");
        }
    }

    private void addUserType() {
        int transaction = currentProgram.startTransaction("TurboHeader real test user type");
        boolean commit = false;
        try {
            StructureDataType user = new StructureDataType(ROOT, "UserKeep", 4,
                    currentProgram.getDataTypeManager());
            user.setDescription("not owned by TurboHeader");
            currentProgram.getDataTypeManager().addDataType(user,
                    DataTypeConflictHandler.REPLACE_HANDLER);
            commit = true;
        }
        finally {
            currentProgram.endTransaction(transaction, commit);
        }
    }

    private boolean hasType(String name) {
        return currentProgram.getDataTypeManager().getDataType(new DataTypePath(ROOT, name)) != null;
    }

    private List<String> snapshot() {
        DataTypeManager manager = currentProgram.getDataTypeManager();
        List<String> result = new ArrayList<>();
        Iterator<DataType> all = manager.getAllDataTypes();
        while (all.hasNext()) {
            DataType type = all.next();
            if (!type.getCategoryPath().getPath().startsWith(ROOT.getPath())) {
                continue;
            }
            StringBuilder row = new StringBuilder(type.getDataTypePath().toString())
                    .append('|').append(type.getLength())
                    .append('|').append(type.getDescription());
            if (type instanceof Composite composite) {
                for (DataTypeComponent component : composite.getDefinedComponents()) {
                    row.append('|').append(component.getOffset())
                            .append(':').append(component.getFieldName())
                            .append(':').append(component.getDataType().getDataTypePath())
                            .append(':').append(component.getLength());
                }
            }
            result.add(row.toString());
        }
        result.sort(Comparator.naturalOrder());
        return result;
    }

    private static final class PopulationCancelMonitor extends TaskMonitorAdapter {
        private boolean population;

        @Override
        public void setMessage(String message) {
            super.setMessage(message);
            population |= message != null && message.startsWith("Populating IL2CPP");
        }

        @Override
        public void checkCancelled() throws CancelledException {
            if (population) {
                throw new CancelledException();
            }
            super.checkCancelled();
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
