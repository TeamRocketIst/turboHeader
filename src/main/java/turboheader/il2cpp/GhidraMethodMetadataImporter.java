package turboheader.il2cpp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/** Imports ScriptMetadataMethod objects and exposes their relocation-slot semantics. */
public final class GhidraMethodMetadataImporter {
    private static final int SAMPLE_LIMIT = 12;
    private static final String METHOD_INFO_POINTER = "MethodInfo*";

    private final Program program;
    private final TaskMonitor monitor;
    private final GhidraMethodImporter typeResolver;
    private final Map<String, Integer> failureCounts = new LinkedHashMap<>();
    private final List<String> failureSamples = new ArrayList<>();
    private int labelsCreated;
    private int labelsReused;
    private int commentsCreated;
    private int typed;

    public GhidraMethodMetadataImporter(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor == null ? TaskMonitor.DUMMY : monitor;
        typeResolver = new GhidraMethodImporter(program, this.monitor);
    }

    public ImportResult importMethods(List<ScriptMethodReader.ScriptMetadataMethod> entries)
            throws Exception {
        long started = System.nanoTime();
        DataType methodInfoPointer = typeResolver.resolveType(METHOD_INFO_POINTER, false);
        Map<Address, GhidraRelocationImporter.Target> relocationTargets = new HashMap<>();
        int transaction = program.startTransaction("TurboHeader IL2CPP method metadata");
        boolean commit = false;
        try {
            monitor.initialize(entries.size());
            monitor.setMessage("IL2CPP method metadata");
            for (ScriptMethodReader.ScriptMetadataMethod entry : entries) {
                monitor.checkCancelled();
                Address address = importEntry(entry, methodInfoPointer);
                if (address != null) {
                    relocationTargets.put(address,
                            GhidraRelocationImporter.Target.method(
                                    address, methodInfoPointer, entry.name()));
                }
                monitor.incrementProgress(1);
            }
            commit = true;
        }
        finally {
            program.endTransaction(transaction, commit);
        }

        int failed = failureCounts.values().stream().mapToInt(Integer::intValue).sum();
        var stats = new ImportStats(entries.size(), labelsCreated, labelsReused,
                commentsCreated, typed, failed, Map.copyOf(failureCounts),
                List.copyOf(failureSamples), System.nanoTime() - started);
        return new ImportResult(stats, Map.copyOf(relocationTargets));
    }

    private Address importEntry(ScriptMethodReader.ScriptMetadataMethod entry,
            DataType methodInfoPointer) {
        Address address;
        try {
            address = program.getImageBase().add(entry.address());
        }
        catch (RuntimeException e) {
            fail("invalid address", entry, e.getMessage());
            return null;
        }
        var block = program.getMemory().getBlock(address);
        if (block == null || block.isExecute()) {
            fail(block == null ? "unmapped address" : "executable address", entry,
                    address.toString());
            return null;
        }

        try {
            applyLabel(address, entry.name());
            applyComment(address, entry.name());
            if (!applyType(address, methodInfoPointer)) {
                fail("typed method metadata conflict", entry, address.toString());
                return null;
            }
        }
        catch (Exception e) {
            fail("annotation failed", entry, e.getMessage());
            return null;
        }
        return address;
    }

    private void applyLabel(Address address, String managedName) throws Exception {
        String name = Il2CppMethodMetadataLabels.target(address.getOffset(), managedName);
        Symbol symbol = program.getSymbolTable().getGlobalSymbol(name, address);
        if (symbol == null) {
            symbol = program.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED);
            labelsCreated++;
        }
        else {
            labelsReused++;
        }
        if (!symbol.isPrimary()) {
            symbol.setPrimary();
        }
    }

    private void applyComment(Address address, String managedName) {
        if (program.getListing().getComment(CommentType.EOL, address) == null) {
            program.getListing().setComment(address, CommentType.EOL,
                    Il2CppMethodMetadataLabels.comment(managedName));
            commentsCreated++;
        }
    }

    private boolean applyType(Address address, DataType dataType) {
        Data existing = program.getListing().getDefinedDataAt(address);
        if (existing != null && existing.getDataType().isEquivalent(dataType)) {
            typed++;
            return true;
        }
        if (existing != null && existing.getBaseDataType() instanceof Pointer pointer &&
                pointer.getDataType() != null) {
            return false;
        }
        CreateDataCmd command = new CreateDataCmd(address, dataType, false,
                ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        if (!command.applyTo(program)) {
            return false;
        }
        typed++;
        return true;
    }

    private void fail(String cause, ScriptMethodReader.ScriptMetadataMethod entry, String detail) {
        failureCounts.merge(cause, 1, Integer::sum);
        if (failureSamples.size() < SAMPLE_LIMIT) {
            failureSamples.add(String.format("0x%x %s: %s%s", entry.address(), entry.name(),
                    cause, detail == null || detail.isBlank() ? "" : " (" + detail + ")"));
        }
    }

    public record ImportResult(ImportStats stats,
            Map<Address, GhidraRelocationImporter.Target> relocationTargets) {
    }

    public record ImportStats(int total, int labelsCreated, int labelsReused,
            int commentsCreated, int typed, int failed, Map<String, Integer> failureCounts,
            List<String> failureSamples, long elapsedNanos) {
        public double elapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }
}
