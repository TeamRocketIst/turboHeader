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

/** Applies labels, comments, and pointer types from the ScriptString table. */
public final class GhidraStringImporter {
    private static final int SAMPLE_LIMIT = 12;
    private static final String STRING_POINTER_TYPE = "System_String_o*";

    private final Program program;
    private final TaskMonitor monitor;
    private final GhidraMethodImporter typeResolver;
    private final Map<String, Integer> failureCounts = new LinkedHashMap<>();
    private final List<String> failureSamples = new ArrayList<>();
    private int labelsCreated;
    private int labelsReused;
    private int commentsCreated;
    private int typed;
    private int primaryLabelsChanged;

    public GhidraStringImporter(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor == null ? TaskMonitor.DUMMY : monitor;
        typeResolver = new GhidraMethodImporter(program, this.monitor);
    }

    public ImportResult importStrings(List<ScriptMethodReader.ScriptString> entries)
            throws Exception {
        long started = System.nanoTime();
        DataType stringPointer = typeResolver.resolveType(STRING_POINTER_TYPE, false);
        Map<Address, GhidraRelocationImporter.Target> relocationTargets = new HashMap<>();
        int transaction = program.startTransaction("TurboHeader IL2CPP strings");
        boolean commit = false;
        try {
            monitor.initialize(entries.size());
            monitor.setMessage("IL2CPP strings");
            for (ScriptMethodReader.ScriptString entry : entries) {
                monitor.checkCancelled();
                Address address = importEntry(entry, stringPointer);
                if (address != null) {
                    relocationTargets.put(address,
                            GhidraRelocationImporter.Target.string(
                                    address, stringPointer, entry.value()));
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
                commentsCreated, typed, primaryLabelsChanged, failed,
                Map.copyOf(failureCounts), List.copyOf(failureSamples),
                System.nanoTime() - started);
        return new ImportResult(stats, Map.copyOf(relocationTargets));
    }

    private Address importEntry(ScriptMethodReader.ScriptString entry, DataType stringPointer) {
        Address address;
        try {
            address = program.getImageBase().add(entry.address());
        }
        catch (RuntimeException e) {
            fail("invalid address", entry, e.getMessage());
            return null;
        }

        var block = program.getMemory().getBlock(address);
        if (block == null) {
            fail("unmapped address", entry, address.toString());
            return null;
        }
        if (block.isExecute()) {
            fail("executable address", entry, address.toString());
            return null;
        }

        try {
            applyLabel(address, entry.value());
            applyComment(address, entry.value());
            if (!applyType(address, stringPointer)) {
                fail("typed string conflict", entry, address.toString());
                return null;
            }
        }
        catch (Exception e) {
            fail("annotation failed", entry, e.getMessage());
            return null;
        }
        return address;
    }

    private void applyLabel(Address address, String value) throws Exception {
        String name = Il2CppStringLabels.label(address.getOffset(), value);
        var symbolTable = program.getSymbolTable();
        Symbol symbol = symbolTable.getGlobalSymbol(name, address);
        if (symbol == null) {
            symbol = symbolTable.createLabel(address, name, SourceType.USER_DEFINED);
            labelsCreated++;
        }
        else {
            labelsReused++;
        }

        if (!symbol.isPrimary()) {
            symbol.setPrimary();
            primaryLabelsChanged++;
        }
    }

    private void applyComment(Address address, String value) {
        if (program.getListing().getComment(CommentType.EOL, address) == null) {
            program.getListing().setComment(address, CommentType.EOL,
                    Il2CppStringLabels.comment(value));
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

    private void fail(String cause, ScriptMethodReader.ScriptString entry, String detail) {
        failureCounts.merge(cause, 1, Integer::sum);
        if (failureSamples.size() < SAMPLE_LIMIT) {
            failureSamples.add(String.format("0x%x: %s%s", entry.address(), cause,
                    detail == null || detail.isBlank() ? "" : " (" + detail + ")"));
        }
    }

    public record ImportResult(ImportStats stats,
            Map<Address, GhidraRelocationImporter.Target> relocationTargets) {
    }

    public record ImportStats(int total, int labelsCreated, int labelsReused,
            int commentsCreated, int typed, int primaryLabelsChanged, int failed,
            Map<String, Integer> failureCounts, List<String> failureSamples, long elapsedNanos) {
        public double elapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }
}
