package turboheader.il2cpp.metadata;

import java.io.IOException;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class Il2CppReferenceGenericCallCatalog {
    static final int MAX_ENTRIES = 1_000_000;
    static final int MAX_SIGNATURE_CHARS = 65_536;
    static final int MAX_CATALOGUE_BYTES = 64 * 1024 * 1024;
    static final int MAX_METHOD_SPEC_INDEX = (1 << 28) - 1;
    static final int HEADER_BYTES = 12;
    static final int ENTRY_HEADER_BYTES = 24;

    private final List<Entry> entries;
    private final Map<Long, Entry> byMethodInfoAddress;
    private final Map<Long, List<Entry>> byMethodAddress;

    private Il2CppReferenceGenericCallCatalog(List<Entry> entries) {
        this.entries = List.copyOf(entries);
        Map<Long, Entry> slots = new LinkedHashMap<>();
        Map<Long, List<Entry>> targets = new LinkedHashMap<>();
        for (Entry entry : entries) {
            slots.put(entry.methodInfoAddress(), entry);
            targets.computeIfAbsent(entry.methodAddress(), ignored -> new ArrayList<>()).add(entry);
        }
        byMethodInfoAddress = Collections.unmodifiableMap(slots);
        targets.replaceAll((address, rows) -> List.copyOf(rows));
        byMethodAddress = Collections.unmodifiableMap(targets);
    }

    public static Optional<Il2CppReferenceGenericCallCatalog> fromScript(
            ScriptMethodReader.ScriptData script) throws IOException {
        if (script.referenceGenericCalls().isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(restored(script.referenceGenericCalls().orElseThrow()));
    }

    static Il2CppReferenceGenericCallCatalog restored(List<Entry> source) throws IOException {
        if (source == null || source.size() > MAX_ENTRIES) {
            throw new IOException("invalid reference-generic catalogue size");
        }
        Map<Long, Entry> slots = new LinkedHashMap<>();
        long size = HEADER_BYTES;
        for (Entry entry : source) {
            if (entry == null || entry.methodInfoAddress() <= 0 || entry.methodAddress() <= 0 ||
                    entry.methodSpecIndex() < 0 || entry.methodSpecIndex() > MAX_METHOD_SPEC_INDEX) {
                throw new IOException("invalid reference-generic catalogue entry");
            }
            size += ENTRY_HEADER_BYTES + (long) signatureBytes(entry.signature()).length;
            if (size > MAX_CATALOGUE_BYTES) {
                throw new IOException("reference-generic catalogue is too large");
            }
            Entry previous = slots.putIfAbsent(entry.methodInfoAddress(), entry);
            if (previous != null) {
                if (!previous.equals(entry)) {
                    throw new IOException("conflicting reference-generic MethodInfo entries");
                }
                continue;
            }
            try {
                ReferenceGenericCallSignature.parse(entry.signature());
            }
            catch (IllegalArgumentException e) {
                throw new IOException("invalid reference-generic physical signature", e);
            }
        }
        var entries = new ArrayList<>(slots.values());
        entries.sort(Comparator.comparingLong(Entry::methodInfoAddress));
        return new Il2CppReferenceGenericCallCatalog(entries);
    }

    static byte[] signatureBytes(String signature) throws IOException {
        if (signature == null || signature.isBlank() || signature.length() > MAX_SIGNATURE_CHARS ||
                signature.codePoints().anyMatch(Character::isISOControl)) {
            throw new IOException("invalid reference-generic signature text");
        }
        try {
            var encoded = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(signature));
            byte[] bytes = new byte[encoded.remaining()];
            encoded.get(bytes);
            return bytes;
        }
        catch (CharacterCodingException e) {
            throw new IOException("invalid reference-generic signature encoding", e);
        }
    }

    public List<Entry> entries() {
        return entries;
    }

    public Optional<Entry> forMethodInfoAddress(long address) {
        return Optional.ofNullable(byMethodInfoAddress.get(address));
    }

    public List<Entry> forMethodAddress(long address) {
        return byMethodAddress.getOrDefault(address, List.of());
    }

    public record Entry(long methodInfoAddress, int methodSpecIndex, long methodAddress,
            String signature) {
    }
}
