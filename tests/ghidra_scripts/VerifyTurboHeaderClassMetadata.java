// Verifies class metadata and vtable dependencies in a real Ghidra database.
// @category Data Types

import java.util.Arrays;
import java.util.List;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.SourceType;
import turboheader.il2cpp.GhidraTypeImporter;
import turboheader.il2cpp.GhidraMetadataImporter;
import turboheader.il2cpp.GhidraRelocationImporter;
import turboheader.il2cpp.GhidraStringImporter;
import turboheader.il2cpp.Il2CppStringLabels;
import turboheader.il2cpp.ScriptMethodReader.ScriptMetadata;
import turboheader.il2cpp.ScriptMethodReader.ScriptString;

public class VerifyTurboHeaderClassMetadata extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Structure object = requireStructure("Cipher_o");
        Structure klass = requireStructure("Cipher_c");
        Structure vtable = requireStructure("Cipher_VTable");
        Structure invokeData = requireStructure("VirtualInvokeData");
        Structure staticFields = requireStructure("Cipher_StaticFields");
        Structure managedArray = requireStructure("Fixture_Int32_array");
        Structure arrayBounds = requireStructure("Il2CppArrayBounds");
        requireStructure("Cipher_StaticValue");
        Structure classPrefix = requireStructure("Il2CppClass_1");
        requireStructure("Il2CppClass_2");
        Structure interfaceOffsetPair = requireStructure("Il2CppRuntimeInterfaceOffsetPair");

        DataTypeComponent klassPointer = requireField(object, "klass", 0);
        require(klassPointer.getDataType() instanceof Pointer,
                "Cipher_o.klass is not a pointer");
        Pointer pointer = (Pointer) klassPointer.getDataType();
        require(pointer.getDataType() != null &&
                pointer.getDataType().getName().equals("Cipher_c"),
                "Cipher_o.klass does not resolve to Cipher_c");

        requireField(klass, "vtable", 40);
        requireVirtualInvokeData(vtable, "_0_Transform", 0);
        requireVirtualInvokeData(vtable, "_1_Reset", 16);
        requireField(invokeData, "methodPtr", 0);
        requireField(invokeData, "method", 8);
        DataTypeComponent interfaceOffsets = requireField(classPrefix, "interfaceOffsets", 8);
        require(interfaceOffsets.getDataType() instanceof Pointer,
                "Il2CppClass_1.interfaceOffsets is not a pointer");
        Pointer interfaceOffsetsPointer = (Pointer) interfaceOffsets.getDataType();
        require(interfaceOffsetsPointer.getDataType() != null &&
                interfaceOffsetsPointer.getDataType().getName()
                        .equals("Il2CppRuntimeInterfaceOffsetPair"),
                "Il2CppClass_1.interfaceOffsets does not resolve to its pair type");
        requireField(interfaceOffsetPair, "interfaceType", 0);
        requireField(interfaceOffsetPair, "offset", 8);
        DataTypeComponent staticFieldsPointer = requireField(klass, "static_fields", 16);
        require(staticFieldsPointer.getDataType() instanceof Pointer,
                "Cipher_c.static_fields is not a pointer");
        Pointer staticPointer = (Pointer) staticFieldsPointer.getDataType();
        require(staticPointer.getDataType() != null &&
                staticPointer.getDataType().getName().equals("Cipher_StaticFields"),
                "Cipher_c.static_fields does not resolve to Cipher_StaticFields");
        requireField(staticFields, "state", 0);
        DataTypeComponent staticValue = requireField(staticFields, "value", 4);
        require(staticValue.getDataType() instanceof Structure &&
                staticValue.getDataType().getName().equals("Cipher_StaticValue"),
                "Cipher_StaticFields.value does not retain its by-value type");
        DataTypeComponent helper = requireField(staticFields, "helper", 8);
        require(helper.getDataType() instanceof Pointer,
                "Cipher_StaticFields.helper is not a pointer");
        Pointer helperPointer = (Pointer) helper.getDataType();
        require(helperPointer.getDataType() != null &&
                helperPointer.getDataType().getName().equals("Cipher_Helper"),
                "Cipher_StaticFields.helper does not retain its opaque target type");
        DataTypeComponent offsets = requireField(staticFields, "offsets", 16);
        require(offsets.getDataType() instanceof Pointer,
                "Cipher_StaticFields.offsets is not a pointer");
        Pointer offsetsPointer = (Pointer) offsets.getDataType();
        require(offsetsPointer.getDataType() != null &&
                offsetsPointer.getDataType().getName().equals("Fixture_Int32_array"),
                "managed array pointer target remained opaque");
        requireField(managedArray, "obj", 0);
        requireField(managedArray, "bounds", 16);
        requireField(managedArray, "max_length", 24);
        requireField(managedArray, "m_Items", 32);
        requireField(arrayBounds, "length", 0);
        requireField(arrayBounds, "lower_bound", 8);
        require(Arrays.stream(staticFields.getDefinedComponents())
                .noneMatch(component -> "thread_cache".equals(component.getFieldName())),
                "thread-static storage was imported into the normal static block");

        requireStructure("Cipher_Helper");
        requireStructure("LooksLikeArrayButIsNot");
        require(currentProgram.getDataTypeManager().getDataType(
                new DataTypePath("/IL2CPP/__opaque", "Cipher_Helper")) == null,
                "defined pointer target remained opaque");
        require(currentProgram.getDataTypeManager().getDataType(
                new DataTypePath(GhidraTypeImporter.ROOT, "ExternalState")) == null,
                "forward declaration was imported as a concrete type");
        require(currentProgram.getDataTypeManager().getDataType(
                new DataTypePath("/IL2CPP/__opaque", "ExternalState")) != null,
                "forward declaration did not retain an opaque target");
        require(currentProgram.getDataTypeManager().getDataType(
                new DataTypePath("/IL2CPP/__opaque", "Cipher_StaticFields")) == null,
                "Cipher_StaticFields remained opaque");
        require(currentProgram.getDataTypeManager().getDataType(
                new DataTypePath("/IL2CPP/__opaque", "Cipher_c")) == null,
                "Cipher_c remained opaque");
        verifyTypedMetadataSlot();
        verifyStringMetadata();
        println("TurboHeader class metadata verification passed");
    }

    private void verifyStringMetadata() throws Exception {
        long relative = 0x750000L;
        Address slot = currentProgram.getImageBase().add(relative);
        while (currentProgram.getMemory().contains(slot)) {
            relative += 0x10000L;
            slot = currentProgram.getImageBase().add(relative);
        }
        var block = createMemoryBlock("turboheader_string_test", slot, new byte[64], false);
        block.setRead(true);
        block.setWrite(false);
        block.setExecute(false);

        int pointerSize = currentProgram.getDefaultPointerSize();
        Address relocationSlot = slot.add(pointerSize * 4L);
        currentProgram.getMemory().setLong(relocationSlot, slot.getOffset());
        var genericPointer = currentProgram.getDataTypeManager().getPointer(null, pointerSize);
        require(new CreateDataCmd(relocationSlot, genericPointer, false,
                ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA).applyTo(currentProgram),
                "could not create the string relocation pointer fixture");
        currentProgram.getRelocationTable().add(relocationSlot, Status.APPLIED, 0,
                new long[] { slot.getOffset() }, new byte[pointerSize], null);

        var entries = List.of(
                new ScriptString(relative, "Attempt "),
                new ScriptString(relative + 8, "line\n\t\"\\é"));
        var firstResult = new GhidraStringImporter(currentProgram, monitor).importStrings(entries);
        var first = firstResult.stats();
        require(first.failed() == 0 && first.labelsCreated() == 2 &&
                first.commentsCreated() == 2 && first.typed() == 2 &&
                first.primaryLabelsChanged() == 0,
                "string metadata was not imported");
        require(Il2CppStringLabels.label(slot.getOffset(), "Attempt ").equals(
                currentProgram.getSymbolTable().getPrimarySymbol(slot).getName()),
                "readable string label is missing");
        require("IL2CPP string: \"Attempt \"".equals(
                currentProgram.getListing().getComment(CommentType.EOL, slot)),
                "string comment is missing");
        requirePointerTarget(slot, "System_String_o",
                "string usage cell is not System_String_o*");

        var firstRelocations = new GhidraRelocationImporter(currentProgram, monitor)
                .importRelocations(firstResult.relocationTargets());
        require(firstRelocations.failed() == 0 && firstRelocations.slotsTyped() == 1 &&
                firstRelocations.stringLabelsCreated() == 1 &&
                firstRelocations.stringCommentsCreated() == 1,
                "string relocation slot was not imported");
        require(Il2CppStringLabels.label(relocationSlot.getOffset(), "Attempt ").equals(
                currentProgram.getSymbolTable().getPrimarySymbol(relocationSlot).getName()),
                "string relocation label is missing");
        var relocatedData = currentProgram.getListing().getDefinedDataAt(relocationSlot);
        require(relocatedData != null && relocatedData.getDataType() instanceof Pointer,
                "string relocation is not pointer data");
        Pointer relocatedOuter = (Pointer) relocatedData.getDataType();
        require(relocatedOuter.getDataType() instanceof Pointer &&
                ((Pointer) relocatedOuter.getDataType()).getDataType() != null &&
                ((Pointer) relocatedOuter.getDataType()).getDataType().getName()
                        .equals("System_String_o"),
                "string relocation is not System_String_o**");

        var secondResult = new GhidraStringImporter(currentProgram, monitor).importStrings(entries);
        var second = secondResult.stats();
        require(second.failed() == 0 && second.labelsCreated() == 0 &&
                second.labelsReused() == 2 && second.commentsCreated() == 0,
                "string import is not idempotent");
        var secondRelocations = new GhidraRelocationImporter(currentProgram, monitor)
                .importRelocations(secondResult.relocationTargets());
        require(secondRelocations.failed() == 0 &&
                secondRelocations.stringLabelsReused() == 1,
                "string relocation import is not idempotent");

        Address protectedSlot = slot.add(16);
        var protectedSymbol = currentProgram.getSymbolTable().createLabel(
                protectedSlot, "Fixture_User_String", SourceType.USER_DEFINED);
        protectedSymbol.setPrimary();
        var protectedResult = new GhidraStringImporter(currentProgram, monitor).importStrings(
                List.of(new ScriptString(relative + 16, "Do not replace"))).stats();
        require(protectedResult.failed() == 0 && protectedResult.labelsCreated() == 1 &&
                protectedResult.primaryLabelsChanged() == 1,
                "canonical string label did not become primary");
        require(Il2CppStringLabels.label(protectedSlot.getOffset(), "Do not replace").equals(
                currentProgram.getSymbolTable().getPrimarySymbol(protectedSlot).getName()),
                "canonical string label is not primary");
        require(currentProgram.getSymbolTable().getGlobalSymbol(
                "Fixture_User_String", protectedSlot) != null,
                "previous user-defined string label was deleted");

        long executableRelative = relative + 0x10000L;
        Address executableSlot = currentProgram.getImageBase().add(executableRelative);
        while (currentProgram.getMemory().contains(executableSlot)) {
            executableRelative += 0x10000L;
            executableSlot = currentProgram.getImageBase().add(executableRelative);
        }
        var executableBlock = createMemoryBlock(
                "turboheader_string_executable_test", executableSlot, new byte[16], false);
        executableBlock.setExecute(true);
        var rejected = new GhidraStringImporter(currentProgram, monitor).importStrings(List.of(
                new ScriptString(executableRelative, "invalid"))).stats();
        require(rejected.failed() == 1 && rejected.labelsCreated() == 0,
                "string importer accepted an executable address");
    }

    private void requireVirtualInvokeData(Structure vtable, String name, int offset) {
        DataTypeComponent component = requireField(vtable, name, offset);
        require(component.getDataType() instanceof Structure &&
                component.getDataType().getName().equals("VirtualInvokeData"),
                vtable.getName() + "." + name + " is not the runtime VirtualInvokeData type");
    }

    private void verifyTypedMetadataSlot() throws Exception {
        long relative = 0x70000000L;
        Address slot = currentProgram.getImageBase().add(relative);
        while (currentProgram.getMemory().contains(slot)) {
            relative += 0x10000L;
            slot = currentProgram.getImageBase().add(relative);
        }
        int pointerSize = currentProgram.getDefaultPointerSize();
        require(pointerSize == 8, "metadata relocation fixture requires a 64-bit program");
        createMemoryBlock("turboheader_metadata_test", slot, new byte[64], false);

        Address relocationSlot = slot.add(pointerSize);
        Address noRelocationSlot = slot.add(pointerSize * 2L);
        Address unrelatedRelocationSlot = slot.add(pointerSize * 3L);
        Address unrelatedTarget = slot.add(pointerSize * 4L);
        Address failedRelocationSlot = slot.add(pointerSize * 5L);
        Address protectedTarget = slot.add(pointerSize * 6L);
        Address protectedRelocationSlot = slot.add(pointerSize * 7L);
        currentProgram.getMemory().setLong(relocationSlot, slot.getOffset());
        currentProgram.getMemory().setLong(noRelocationSlot, slot.getOffset());
        currentProgram.getMemory().setLong(unrelatedRelocationSlot, unrelatedTarget.getOffset());
        currentProgram.getMemory().setLong(failedRelocationSlot, slot.getOffset());
        currentProgram.getMemory().setLong(protectedRelocationSlot, protectedTarget.getOffset());

        var genericPointer = currentProgram.getDataTypeManager().getPointer(null, pointerSize);
        require(new CreateDataCmd(relocationSlot, genericPointer, false,
                ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA).applyTo(currentProgram),
                "could not create the relocation pointer fixture");
        require(new CreateDataCmd(noRelocationSlot, genericPointer, false,
                ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA).applyTo(currentProgram),
                "could not create the non-relocation pointer fixture");
        require(new CreateDataCmd(unrelatedRelocationSlot, genericPointer, false,
                ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA).applyTo(currentProgram),
                "could not create the unrelated relocation pointer fixture");
        require(new CreateDataCmd(failedRelocationSlot, genericPointer, false,
                ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA).applyTo(currentProgram),
                "could not create the failed relocation pointer fixture");
        var protectedPointer = currentProgram.getDataTypeManager().getPointer(
                VoidDataType.dataType, pointerSize);
        require(new CreateDataCmd(protectedRelocationSlot, protectedPointer, false,
                ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA).applyTo(currentProgram),
                "could not create the protected relocation pointer fixture");
        currentProgram.getRelocationTable().add(relocationSlot, Status.APPLIED, 0,
                new long[] { slot.getOffset() }, new byte[pointerSize], null);
        currentProgram.getRelocationTable().add(unrelatedRelocationSlot, Status.APPLIED, 0,
                new long[] { unrelatedTarget.getOffset() }, new byte[pointerSize], null);
        currentProgram.getRelocationTable().add(failedRelocationSlot, Status.FAILURE, 0,
                new long[] { slot.getOffset() }, new byte[pointerSize], null);
        currentProgram.getRelocationTable().add(protectedRelocationSlot, Status.APPLIED, 0,
                new long[] { protectedTarget.getOffset() }, new byte[pointerSize], null);

        var entry = new ScriptMetadata(relative, "Fixture.Cipher_TypeInfo", "Cipher_c*");
        var firstResult = new GhidraMetadataImporter(currentProgram, monitor)
                .importMetadata(List.of(entry));
        var first = firstResult.stats();
        var firstRelocations = new GhidraRelocationImporter(currentProgram, monitor)
                .importRelocations(firstResult.relocationTargets());
        require(first.failed() == 0 && first.typed() == 1 && first.labelsCreated() == 1 &&
                firstRelocations.failed() == 0 && firstRelocations.slotsTyped() == 1,
                "typed metadata slot was not imported");

        var data = currentProgram.getListing().getDefinedDataAt(slot);
        require(data != null && data.getDataType() instanceof Pointer,
                "metadata slot is not pointer data");
        Pointer pointer = (Pointer) data.getDataType();
        require(pointer.getDataType() != null && pointer.getDataType().getName().equals("Cipher_c"),
                "metadata slot does not point to Cipher_c");
        require("Fixture.Cipher_TypeInfo".equals(
                currentProgram.getListing().getComment(CommentType.EOL, slot)),
                "metadata slot comment is missing");

        var relocatedData = currentProgram.getListing().getDefinedDataAt(relocationSlot);
        require(relocatedData != null && relocatedData.getDataType() instanceof Pointer,
                "relocation slot is not pointer data");
        Pointer outerPointer = (Pointer) relocatedData.getDataType();
        require(outerPointer.getDataType() instanceof Pointer,
                "relocation slot did not gain one pointer level");
        Pointer innerPointer = (Pointer) outerPointer.getDataType();
        require(innerPointer.getDataType() != null &&
                innerPointer.getDataType().getName().equals("Cipher_c"),
                "relocation slot does not ultimately point to Cipher_c");

        requireGenericPointer(noRelocationSlot,
                "slot without relocation was changed");
        requireGenericPointer(unrelatedRelocationSlot,
                "relocation to an unrelated target was changed");
        requireGenericPointer(failedRelocationSlot,
                "failed relocation was changed");
        requirePointerTarget(protectedRelocationSlot, "void",
                "unrelated typed relocation was changed");

        var secondResult = new GhidraMetadataImporter(currentProgram, monitor)
                .importMetadata(List.of(entry));
        var second = secondResult.stats();
        var secondRelocations = new GhidraRelocationImporter(currentProgram, monitor)
                .importRelocations(secondResult.relocationTargets());
        require(second.failed() == 0 && second.typed() == 1 && second.labelsCreated() == 0 &&
                secondRelocations.failed() == 0 && secondRelocations.slotsTyped() == 1,
                "metadata slot import is not idempotent");

        var protectedEntry = new ScriptMetadata(relative + pointerSize * 6L,
                "Fixture.Protected_TypeInfo", "Cipher_c*");
        var protectedImport = new GhidraMetadataImporter(currentProgram, monitor)
                .importMetadata(List.of(protectedEntry));
        var protectedResult = protectedImport.stats();
        var protectedRelocations = new GhidraRelocationImporter(currentProgram, monitor)
                .importRelocations(protectedImport.relocationTargets());
        require(protectedResult.typed() == 1 && protectedResult.failed() == 0 &&
                protectedRelocations.slotsTyped() == 0 && protectedRelocations.failed() == 1 &&
                protectedRelocations.failureCounts().getOrDefault(
                        "typed relocation slot conflict", 0) == 1,
                "typed relocation conflict was not reported");
        requirePointerTarget(protectedRelocationSlot, "void",
                "typed relocation conflict was overwritten");

        long executableRelative = relative + 0x10000L;
        Address executableSlot = currentProgram.getImageBase().add(executableRelative);
        while (currentProgram.getMemory().contains(executableSlot)) {
            executableRelative += 0x10000L;
            executableSlot = currentProgram.getImageBase().add(executableRelative);
        }
        var executableBlock = createMemoryBlock(
                "turboheader_metadata_executable_test", executableSlot, new byte[16], false);
        executableBlock.setExecute(true);
        var rejected = new GhidraMetadataImporter(currentProgram, monitor).importMetadata(List.of(
                new ScriptMetadata(executableRelative, "Fixture.Invalid_TypeInfo", "Cipher_c*")))
                .stats();
        require(rejected.failed() == 1 && rejected.typed() == 0 && rejected.labelsCreated() == 0,
                "metadata importer accepted an executable slot");
    }

    private void requireGenericPointer(Address address, String message) {
        var data = currentProgram.getListing().getDefinedDataAt(address);
        require(data != null && data.getDataType() instanceof Pointer, message);
        require(((Pointer) data.getDataType()).getDataType() == null, message);
    }

    private void requirePointerTarget(Address address, String targetName, String message) {
        var data = currentProgram.getListing().getDefinedDataAt(address);
        require(data != null && data.getDataType() instanceof Pointer, message);
        Pointer pointer = (Pointer) data.getDataType();
        require(pointer.getDataType() != null &&
                targetName.equals(pointer.getDataType().getName()), message);
    }

    private Structure requireStructure(String name) {
        var type = currentProgram.getDataTypeManager().getDataType(
                new DataTypePath(GhidraTypeImporter.ROOT, name));
        require(type instanceof Structure, name + " is missing");
        return (Structure) type;
    }

    private static DataTypeComponent requireField(Structure structure, String name, int offset) {
        return Arrays.stream(structure.getDefinedComponents())
                .filter(component -> name.equals(component.getFieldName()) &&
                        component.getOffset() == offset)
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        structure.getName() + "." + name + " is missing"));
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
