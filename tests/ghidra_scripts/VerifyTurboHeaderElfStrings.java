// @category Test

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import static ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.SourceType;
import turboheader.il2cpp.Il2CppMetadataImportService;
import turboheader.il2cpp.metadata.GhidraStringImporter;
import turboheader.il2cpp.metadata.Il2CppStringLabels;
import turboheader.il2cpp.metadata.ScriptMethodReader.ScriptString;

public class VerifyTurboHeaderElfStrings extends GhidraScript {
    private int fixtureIndex;

    @Override
    protected void run() throws Exception {
        int[] tableTypes = { SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_HASH,
                SHT_DYNAMIC, SHT_REL, SHT_DYNSYM, SHT_GNU_HASH };
        for (int type : tableTypes) {
            verifyTable(type, true, ByteOrder.LITTLE_ENDIAN);
        }
        verifyTable(SHT_HASH, false, ByteOrder.LITTLE_ENDIAN);
        verifyTable(SHT_HASH, true, ByteOrder.BIG_ENDIAN);
        verifyOrdinaryDataConflict();
        verifyMalformedTable();
        println("TurboHeader ELF string candidate verification passed");
    }

    private void verifyTable(int type, boolean is64, ByteOrder order) throws Exception {
        byte[] bytes = elf(type, is64, order);
        Address start = map(bytes, "renamed_table");
        Address table = start.add(8);
        var data = createData(table, new ArrayDataType(QWordDataType.dataType, 8, 8));
        var label = createLabel(table, "Fixture_Table_" + fixtureIndex, true, SourceType.USER_DEFINED);
        currentProgram.getListing().setComment(table, CommentType.EOL, "Keep this table");
        byte[] before = getBytes(start, 0x60);
        var result = new GhidraStringImporter(currentProgram, monitor).importStrings(List.of(
                string(table, "sample"), string(table.add(24), "middle"),
                string(table.subtract(4), "overlap"), string(table.add(60), "end overlap"),
                string(table.add(64), "valid")));
        var stats = result.stats();
        require(stats.total() == 5 && stats.skipped() == 4 && stats.failed() == 0 &&
                stats.typed() == 1 && stats.labelsCreated() == 1 && stats.commentsCreated() == 1,
                "ELF table candidates were not separated from valid slots");
        require(result.relocationTargets().size() == 1 &&
                result.relocationTargets().containsKey(table.add(64)),
                "skipped table entered relocation propagation");
        require(java.util.Arrays.equals(before, getBytes(start, 0x60)), "ELF bytes changed");
        require(currentProgram.getListing().getDefinedDataAt(table).getDataType()
                .isEquivalent(data.getDataType()), "ELF array changed");
        require(currentProgram.getSymbolTable().getPrimarySymbol(table).equals(label),
                "existing ELF label changed");
        require("Keep this table".equals(currentProgram.getListing().getComment(CommentType.EOL, table)),
                "existing ELF comment changed");
        require(currentProgram.getSymbolTable().getGlobalSymbol(
                Il2CppStringLabels.label(table.getOffset(), "sample"), table) == null,
                "skipped ELF candidate acquired a string label");
        require(currentProgram.getListing().getComment(CommentType.EOL, table.add(24)) == null,
                "skipped ELF candidate acquired a comment");

        var script = Files.createTempFile("elf-string-candidates", ".json");
        try {
            Files.writeString(script, "{\"ScriptMethod\":[],\"ScriptString\":[{\"Address\":" +
                    table.subtract(currentProgram.getImageBase()) + ",\"Value\":\"sample\"}]}");
            var warnings = new ArrayList<String>();
            new Il2CppMetadataImportService(currentProgram, monitor, unused -> { }, warnings::add)
                    .importScript(script);
            require(warnings.stream().anyMatch(line -> line.contains("ELF bookkeeping tables: 1.")),
                    "skipped candidate did not produce a warning");
        }
        finally {
            Files.deleteIfExists(script);
        }
    }

    private void verifyOrdinaryDataConflict() throws Exception {
        Address start = map(elf(SHT_PROGBITS, true, ByteOrder.LITTLE_ENDIAN), ".gnu.hash");
        Address slot = start.add(8);
        var data = createData(slot, new ArrayDataType(QWordDataType.dataType, 8, 8));
        var stats = new GhidraStringImporter(currentProgram, monitor)
                .importStrings(List.of(string(slot, "conflict"))).stats();
        require(stats.skipped() == 0 && stats.failed() == 1,
                "ordinary data conflict was hidden by the block name");
        require(currentProgram.getListing().getDefinedDataAt(slot).getDataType()
                .isEquivalent(data.getDataType()), "conflicting data was overwritten");
        var script = Files.createTempFile("elf-string-conflict", ".json");
        try {
            Files.writeString(script, "{\"ScriptMethod\":[],\"ScriptString\":[{\"Address\":" +
                    slot.subtract(currentProgram.getImageBase()) + ",\"Value\":\"conflict\"}]}");
            try {
                new Il2CppMetadataImportService(currentProgram, monitor, unused -> { }, unused -> { })
                        .importScript(script);
                throw new AssertionError("genuine string conflict no longer fails the import");
            }
            catch (IllegalStateException expected) {
                require(expected.getMessage().contains("did not apply 1 of 1 strings"),
                        "import failed for an unexpected reason");
            }
        }
        finally {
            Files.deleteIfExists(script);
        }
    }

    private void verifyMalformedTable() throws Exception {
        byte[] bytes = elf(SHT_HASH, true, ByteOrder.LITTLE_ENDIAN);
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putLong(0x260, Long.MAX_VALUE);
        Address slot = map(bytes, "malformed_table").add(8);
        try {
            new GhidraStringImporter(currentProgram, monitor)
                    .importStrings(List.of(string(slot, "invalid")));
            throw new AssertionError("invalid ELF extent accepted");
        }
        catch (IOException expected) {
            require(currentProgram.getListing().getDefinedDataAt(slot) == null,
                    "invalid ELF input modified data");
            require(currentProgram.getSymbolTable().getPrimarySymbol(slot) == null,
                    "invalid ELF input created a label");
        }
    }

    private Address map(byte[] bytes, String name) throws Exception {
        fixtureIndex++;
        Address start = currentProgram.getImageBase().add(0x72000000L + fixtureIndex * 0x1000L);
        var file = currentProgram.getMemory().createFileBytes("elf_fixture_" + fixtureIndex,
                0, bytes.length, new ByteArrayInputStream(bytes), monitor);
        currentProgram.getMemory().createInitializedBlock(name + '_' + fixtureIndex,
                start, file, 0xf8, 0x60, false);
        return start;
    }

    private ScriptString string(Address address, String value) {
        return new ScriptString(address.subtract(currentProgram.getImageBase()), value);
    }

    private byte[] elf(int type, boolean is64, ByteOrder order) {
        var buffer = ByteBuffer.allocate(0x300).order(order);
        buffer.put(new byte[] { 0x7f, 'E', 'L', 'F', (byte) (is64 ? 2 : 1),
                (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1 });
        buffer.putShort(16, (short) 3);
        buffer.putShort(18, (short) (is64 ? 183 : 40));
        buffer.putInt(20, 1);
        int entrySize = is64 ? 64 : 40;
        if (is64) {
            buffer.putLong(40, 0x200);
            buffer.putShort(52, (short) 64);
            buffer.putShort(58, (short) entrySize);
            buffer.putShort(60, (short) 2);
        }
        else {
            buffer.putInt(32, 0x200);
            buffer.putShort(40, (short) 52);
            buffer.putShort(46, (short) entrySize);
            buffer.putShort(48, (short) 2);
        }
        int section = 0x200 + entrySize;
        buffer.putInt(section + 4, type);
        if (is64) {
            buffer.putLong(section + 8, 2);
            buffer.putLong(section + 24, 0x100);
            buffer.putLong(section + 32, 0x40);
        }
        else {
            buffer.putInt(section + 8, 2);
            buffer.putInt(section + 16, 0x100);
            buffer.putInt(section + 20, 0x40);
        }
        return buffer.array();
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
