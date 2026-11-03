package turboheader.il2cpp.metadata;

import java.io.IOException;
import java.util.Arrays;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.FileBytesProvider;
import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Finds mapped ELF tables that cannot hold runtime string pointers. */
final class ElfMetadataTables {
    private static final int MAX_SECTIONS = 65536;
    private static final int MAX_FILES = 128;

    private ElfMetadataTables() {
    }

    static AddressSet read(Program program, TaskMonitor monitor)
            throws IOException, CancelledException {
        AddressSet tables = new AddressSet();
        var memory = program.getMemory();
        var files = memory.getAllFileBytes();
        if (files.size() > MAX_FILES) {
            throw new IOException("too many source files to inspect ELF string slots");
        }
        for (var file : files) {
            monitor.checkCancelled();
            try (var provider = new FileBytesProvider(file)) {
                if (provider.length() < ElfConstants.MAGIC_BYTES.length ||
                        !Arrays.equals(provider.readBytes(0, ElfConstants.MAGIC_BYTES.length),
                                ElfConstants.MAGIC_BYTES)) {
                    continue;
                }
                ElfHeader header = new ElfHeader(provider, null);
                int count = header.getSectionHeaderCount();
                int entrySize = Short.toUnsignedInt(header.e_shentsize());
                long offset = header.e_shoff();
                if (count == 0) continue;
                if (count < 0 || count > MAX_SECTIONS ||
                        entrySize != (header.is64Bit() ? 64 : 40) ||
                        offset < 0 || offset > provider.length() ||
                        (long) count * entrySize > provider.length() - offset) {
                    throw new IOException("invalid ELF section table for string import");
                }
                var reader = new BinaryReader(provider, header.isLittleEndian());
                for (int index = 0; index < count; index++) {
                    monitor.checkCancelled();
                    var section = new ElfSectionHeader(
                            reader.clone(offset + (long) index * entrySize), header);
                    if (!isTable(section.getType()) ||
                            (section.getFlags() & ElfSectionHeaderConstants.SHF_ALLOC) == 0) {
                        continue;
                    }
                    long start = section.getOffset();
                    long size = section.getSize();
                    if (start < 0 || size < 0 || start > provider.length() ||
                            size > provider.length() - start) {
                        throw new IOException("invalid ELF metadata table extent");
                    }
                    if (size == 0) continue;
                    long end = start + size - 1;
                    for (var block : memory.getBlocks()) {
                        monitor.checkCancelled();
                        for (var source : block.getSourceInfos()) {
                            if (source.getFileBytes().filter(file::equals).isEmpty()) continue;
                            long sourceStart = source.getFileBytesOffset();
                            if (sourceStart < 0 || source.getLength() <= 0 ||
                                    sourceStart > provider.length() ||
                                    source.getLength() > provider.length() - sourceStart) continue;
                            long first = Math.max(start, sourceStart);
                            long last = Math.min(end, sourceStart + source.getLength() - 1);
                            if (first > last) continue;
                            var mappedStart = source.locateAddressForFileOffset(first);
                            var mappedEnd = source.locateAddressForFileOffset(last);
                            if (mappedStart != null && mappedEnd != null) {
                                tables.add(mappedStart, mappedEnd);
                            }
                        }
                    }
                }
            }
            catch (ElfException e) {
                throw new IOException("cannot inspect ELF tables for string import", e);
            }
        }
        return tables;
    }

    private static boolean isTable(int type) {
        return switch (type) {
            case ElfSectionHeaderConstants.SHT_HASH,
                 ElfSectionHeaderConstants.SHT_GNU_HASH,
                 ElfSectionHeaderConstants.SHT_SYMTAB,
                 ElfSectionHeaderConstants.SHT_DYNSYM,
                 ElfSectionHeaderConstants.SHT_STRTAB,
                 ElfSectionHeaderConstants.SHT_REL,
                 ElfSectionHeaderConstants.SHT_RELA,
                 ElfSectionHeaderConstants.SHT_DYNAMIC -> true;
            default -> false;
        };
    }
}
