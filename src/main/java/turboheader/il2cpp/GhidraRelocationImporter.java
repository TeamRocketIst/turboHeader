package turboheader.il2cpp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/** Types IL2CPP metadata, method-metadata, and string slots in one relocation-table pass. */
public final class GhidraRelocationImporter {
    private static final int SAMPLE_LIMIT = 12;

    private final Program program;
    private final TaskMonitor monitor;
    private final Map<String, Integer> failureCounts = new LinkedHashMap<>();
    private final List<String> failureSamples = new ArrayList<>();
    private int relocationsScanned;
    private int slotsMatched;
    private int slotsTyped;
    private int stringLabelsCreated;
    private int stringLabelsReused;
    private int stringCommentsCreated;
    private int methodLabelsCreated;
    private int methodLabelsReused;
    private int methodCommentsCreated;

    public GhidraRelocationImporter(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor == null ? TaskMonitor.DUMMY : monitor;
    }

    public ImportStats importRelocations(Map<Address, Target> targets) throws Exception {
        long started = System.nanoTime();
        int transaction = program.startTransaction("TurboHeader IL2CPP relocation slots");
        boolean commit = false;
        try {
            var relocationTable = program.getRelocationTable();
            monitor.initialize(relocationTable.getSize());
            monitor.setMessage("IL2CPP metadata and string relocation slots");
            importRelocations(targets, relocationTable.getRelocations());
            commit = true;
        }
        finally {
            program.endTransaction(transaction, commit);
        }
        int failed = failureCounts.values().stream().mapToInt(Integer::intValue).sum();
        return new ImportStats(relocationsScanned, slotsMatched, slotsTyped,
                stringLabelsCreated, stringLabelsReused, stringCommentsCreated,
                methodLabelsCreated, methodLabelsReused, methodCommentsCreated, failed,
                Map.copyOf(failureCounts), List.copyOf(failureSamples),
                System.nanoTime() - started);
    }

    private void importRelocations(Map<Address, Target> targets,
            Iterator<Relocation> relocations) throws Exception {
        Set<Address> processedSlots = new HashSet<>();
        Set<Address> runtimeMetadataSlots = new HashSet<>();
        Map<Address, String> methodMetadataNames = new HashMap<>();
        while (relocations.hasNext()) {
            monitor.checkCancelled();
            Relocation relocation = relocations.next();
            relocationsScanned++;
            monitor.incrementProgress(1);
            Status status = relocation.getStatus();
            if (status != Status.APPLIED && status != Status.APPLIED_OTHER) {
                continue;
            }

            Address slot = relocation.getAddress();
            var block = program.getMemory().getBlock(slot);
            if (block == null || block.isExecute()) {
                continue;
            }

            Data existing = program.getListing().getDefinedDataAt(slot);
            if (existing == null || !existing.isPointer() ||
                    !(existing.getValue() instanceof Address targetAddress)) {
                continue;
            }

            Target target = targets.get(targetAddress);
            if (target == null || slot.equals(targetAddress) || !processedSlots.add(slot)) {
                continue;
            }
            slotsMatched++;

            DataType slotType = program.getDataTypeManager().getPointer(
                    target.dataType(), program.getDefaultPointerSize());
            if (!applyType(slot, existing, slotType, target)) {
                continue;
            }
            runtimeMetadataSlots.add(slot);
            if (target.kind() == TargetKind.STRING) {
                annotateStringSlot(slot, target.stringValue());
            }
            else if (target.kind() == TargetKind.METHOD) {
                annotateMethodSlot(slot, target.managedName());
                methodMetadataNames.put(slot, target.managedName());
            }
        }
        Il2CppProgramFacts.replaceRuntimeMetadataSlots(program, runtimeMetadataSlots);
        Il2CppProgramFacts.replaceMethodMetadataNames(program, methodMetadataNames);
    }

    private boolean applyType(Address slot, Data existing, DataType slotType, Target target) {
        if (existing.getDataType().isEquivalent(slotType)) {
            slotsTyped++;
            return true;
        }
        if (existing.getBaseDataType() instanceof Pointer pointer &&
                pointer.getDataType() != null) {
            fail("typed relocation slot conflict", slot, target, null);
            return false;
        }

        CreateDataCmd command = new CreateDataCmd(slot, slotType, false,
                ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        if (!command.applyTo(program)) {
            fail("relocation slot data creation failed", slot, target,
                    command.getStatusMsg());
            return false;
        }
        slotsTyped++;
        return true;
    }

    private void annotateStringSlot(Address slot, String value) {
        try {
            String name = Il2CppStringLabels.label(slot.getOffset(), value);
            var symbolTable = program.getSymbolTable();
            Symbol symbol = symbolTable.getGlobalSymbol(name, slot);
            if (symbol == null) {
                symbol = symbolTable.createLabel(slot, name, SourceType.USER_DEFINED);
                stringLabelsCreated++;
            }
            else {
                stringLabelsReused++;
            }
            if (!symbol.isPrimary()) {
                symbol.setPrimary();
            }
            if (program.getListing().getComment(CommentType.EOL, slot) == null) {
                program.getListing().setComment(slot, CommentType.EOL,
                        Il2CppStringLabels.comment(value));
                stringCommentsCreated++;
            }
        }
        catch (Exception e) {
            fail("string relocation annotation failed", slot, null, e.getMessage());
        }
    }

    private void annotateMethodSlot(Address slot, String managedName) {
        try {
            String name = Il2CppMethodMetadataLabels.pointer(slot.getOffset(), managedName);
            var symbolTable = program.getSymbolTable();
            Symbol symbol = symbolTable.getGlobalSymbol(name, slot);
            if (symbol == null) {
                symbol = symbolTable.createLabel(slot, name, SourceType.USER_DEFINED);
                methodLabelsCreated++;
            }
            else {
                methodLabelsReused++;
            }
            if (!symbol.isPrimary()) {
                symbol.setPrimary();
            }
            if (program.getListing().getComment(CommentType.EOL, slot) == null) {
                program.getListing().setComment(slot, CommentType.EOL,
                        Il2CppMethodMetadataLabels.comment(managedName));
                methodCommentsCreated++;
            }
        }
        catch (Exception e) {
            fail("method relocation annotation failed", slot, null, e.getMessage());
        }
    }

    private void fail(String cause, Address slot, Target target, String detail) {
        failureCounts.merge(cause, 1, Integer::sum);
        if (failureSamples.size() < SAMPLE_LIMIT) {
            String targetDescription = target == null ? "" : " -> " + target.description();
            failureSamples.add(slot + targetDescription + ": " + cause +
                    (detail == null || detail.isBlank() ? "" : " (" + detail + ")"));
        }
    }

    public enum TargetKind {
        METADATA,
        METHOD,
        STRING
    }

    public record Target(Address address, DataType dataType, TargetKind kind,
            String stringValue, String managedName, String description) {
        public Target {
            if (address == null || dataType == null || kind == null || description == null) {
                throw new IllegalArgumentException("relocation target fields must not be null");
            }
            if (kind == TargetKind.STRING && stringValue == null) {
                throw new IllegalArgumentException("string target value must not be null");
            }
            if (kind == TargetKind.METHOD && managedName == null) {
                throw new IllegalArgumentException("method target name must not be null");
            }
        }

        public static Target string(Address address, DataType dataType, String value) {
            return new Target(address, dataType, TargetKind.STRING, value, null,
                    Il2CppStringLabels.label(address.getOffset(), value));
        }

        public static Target metadata(Address address, DataType dataType, String name) {
            return new Target(address, dataType, TargetKind.METADATA, null, null, name);
        }

        public static Target method(Address address, DataType dataType, String managedName) {
            return new Target(address, dataType, TargetKind.METHOD, null, managedName,
                    Il2CppMethodMetadataLabels.target(address.getOffset(), managedName));
        }
    }

    public record ImportStats(int relocationsScanned, int slotsMatched, int slotsTyped,
            int stringLabelsCreated, int stringLabelsReused, int stringCommentsCreated,
            int methodLabelsCreated, int methodLabelsReused, int methodCommentsCreated,
            int failed, Map<String, Integer> failureCounts, List<String> failureSamples,
            long elapsedNanos) {
        public double elapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }
}
