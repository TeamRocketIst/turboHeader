package turboheader.il2cpp.analysis;

import java.util.Collections;
import java.util.HashSet;
import java.util.NavigableMap;
import java.util.Set;
import java.util.TreeMap;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import turboheader.il2cpp.metadata.Il2CppInterfaceDispatchCatalog;

final class GhidraTypeInfoSources {
    private GhidraTypeInfoSources() {
    }

    static NavigableMap<Long, Integer> collect(Program program,
            Il2CppInterfaceDispatchCatalog catalog) {
        NavigableMap<Long, Integer> result = new TreeMap<>();
        NavigableMap<Long, Integer> typeIdsByTarget = new TreeMap<>();
        NavigableMap<Long, Integer> typeIdsByGotSource = new TreeMap<>();
        Address imageBase = program.getImageBase();
        for (var entry : catalog.typeIdsByMetadataAddress().entrySet()) {
            Address target = imageBase.add(entry.getKey());
            result.put(target.getOffset(), entry.getValue());
            typeIdsByTarget.put(target.getOffset(), entry.getValue());
        }

        Set<Long> conflicts = new HashSet<>();
        for (var entry : typeIdsByTarget.entrySet()) {
            Address target = imageBase.getAddressSpace().getAddress(entry.getKey());
            var references = program.getReferenceManager().getReferencesTo(target);
            while (references.hasNext()) {
                Reference reference = references.next();
                Address source = reference.getFromAddress();
                if (!validSource(program, source, target)) {
                    continue;
                }
                long sourceOffset = source.getOffset();
                if (conflicts.contains(sourceOffset)) {
                    continue;
                }
                Integer previous = typeIdsByGotSource.putIfAbsent(
                        sourceOffset, entry.getValue());
                if (previous != null && previous.intValue() != entry.getValue()) {
                    typeIdsByGotSource.remove(sourceOffset);
                    conflicts.add(sourceOffset);
                }
            }
        }
        for (var entry : typeIdsByGotSource.entrySet()) {
            result.putIfAbsent(entry.getKey(), entry.getValue());
        }
        return Collections.unmodifiableNavigableMap(result);
    }

    private static boolean validSource(Program program, Address source, Address target) {
        MemoryBlock block = program.getMemory().getBlock(source);
        Data data = program.getListing().getDataAt(source);
        if (block == null || data == null) {
            return false;
        }

        Reference[] references = data.getValueReferences();
        Reference reference = references.length == 1 ? references[0] : null;
        Object value = data.getValue();
        var evidence = new TypeInfoSourcePolicy.Evidence(
                data.getLength(), data.isPointer(), block.isRead(), block.isWrite(),
                block.isExecute(), references.length,
                reference != null && reference.getReferenceType().isData(),
                reference != null && reference.isPrimary(),
                value instanceof Address address && address.equals(target) &&
                        reference != null && reference.getToAddress().equals(target));
        return TypeInfoSourcePolicy.accepts(program.getDefaultPointerSize(), evidence);
    }
}
