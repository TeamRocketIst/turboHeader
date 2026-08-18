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
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.task.TaskMonitor;

/** Applies names and pointer types from the ScriptMetadata table. */
public final class GhidraMetadataImporter {
    private static final int SAMPLE_LIMIT = 12;

    private final Program program;
    private final TaskMonitor monitor;
    private final GhidraMethodImporter typeResolver;
    private final Map<String, Integer> failureCounts = new LinkedHashMap<>();
    private final List<String> failureSamples = new ArrayList<>();
    private int labels;
    private int typed;

    public GhidraMetadataImporter(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor == null ? TaskMonitor.DUMMY : monitor;
        this.typeResolver = new GhidraMethodImporter(program, this.monitor);
    }

    public ImportResult importMetadata(List<ScriptMethodReader.ScriptMetadata> entries)
            throws Exception {
        long started = System.nanoTime();
        Map<Address, GhidraRelocationImporter.Target> typedTargets = new HashMap<>();
        int transaction = program.startTransaction("TurboHeader IL2CPP metadata slots");
        boolean commit = false;
        try {
            monitor.initialize(entries.size());
            monitor.setMessage("IL2CPP metadata slots");
            for (ScriptMethodReader.ScriptMetadata entry : entries) {
                monitor.checkCancelled();
                TypedMetadata imported = importEntry(entry);
                if (imported != null) {
                    typedTargets.put(imported.address(),
                            GhidraRelocationImporter.Target.metadata(
                                    imported.address(), imported.dataType(), entry.name()));
                }
                monitor.incrementProgress(1);
            }
            commit = true;
        }
        finally {
            program.endTransaction(transaction, commit);
        }
        int failed = failureCounts.values().stream().mapToInt(Integer::intValue).sum();
        var stats = new ImportStats(entries.size(), labels, typed, failed,
                Map.copyOf(failureCounts), List.copyOf(failureSamples),
                System.nanoTime() - started);
        return new ImportResult(stats, Map.copyOf(typedTargets));
    }

    private TypedMetadata importEntry(ScriptMethodReader.ScriptMetadata entry) {
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

        String name = SymbolUtilities.replaceInvalidChars(entry.name(), true);
        try {
            Symbol symbol = program.getSymbolTable().getGlobalSymbol(name, address);
            if (symbol == null) {
                symbol = program.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED);
                labels++;
            }
            if (!symbol.isPrimary()) {
                symbol.setPrimary();
            }
            if (program.getListing().getComment(CommentType.EOL, address) == null) {
                program.getListing().setComment(address, CommentType.EOL, entry.name());
            }
        }
        catch (Exception e) {
            fail("label creation failed", entry, e.getMessage());
            return null;
        }

        if (entry.signature() == null || entry.signature().isBlank()) {
            return null;
        }

        DataType dataType;
        try {
            dataType = typeResolver.resolveType(entry.signature(), false);
        }
        catch (IllegalArgumentException e) {
            fail("invalid data type", entry, e.getMessage());
            return null;
        }

        Data existing = program.getListing().getDefinedDataAt(address);
        if (existing != null && existing.getDataType().isEquivalent(dataType)) {
            typed++;
            return new TypedMetadata(entry, address, dataType);
        }
        CreateDataCmd command = new CreateDataCmd(address, dataType, false,
                ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
        if (!command.applyTo(program)) {
            fail("data creation failed", entry, command.getStatusMsg());
            return null;
        }
        typed++;
        return new TypedMetadata(entry, address, dataType);
    }

    private void fail(String cause, ScriptMethodReader.ScriptMetadata entry, String detail) {
        failureCounts.merge(cause, 1, Integer::sum);
        if (failureSamples.size() < SAMPLE_LIMIT) {
            failureSamples.add(String.format("0x%x %s: %s%s", entry.address(), entry.name(),
                    cause, detail == null || detail.isBlank() ? "" : " (" + detail + ")"));
        }
    }

    private record TypedMetadata(ScriptMethodReader.ScriptMetadata entry, Address address,
            DataType dataType) {
    }

    public record ImportResult(ImportStats stats,
            Map<Address, GhidraRelocationImporter.Target> relocationTargets) {
    }

    public record ImportStats(int total, int labelsCreated, int typed, int failed,
            Map<String, Integer> failureCounts, List<String> failureSamples, long elapsedNanos) {
        public double elapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }
}
