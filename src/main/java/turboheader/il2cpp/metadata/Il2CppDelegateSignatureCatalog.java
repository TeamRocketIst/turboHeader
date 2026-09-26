package turboheader.il2cpp.metadata;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Exact native delegate signatures keyed by IL2CPP type identity. */
public final class Il2CppDelegateSignatureCatalog {
    private final List<Entry> entries;
    private final Map<Integer, Entry> byTypeId;
    private final Map<String, String> byObjectType;

    private Il2CppDelegateSignatureCatalog(List<Entry> entries) {
        this.entries = List.copyOf(entries);
        Map<Integer, Entry> types = new LinkedHashMap<>();
        Map<String, String> objects = new LinkedHashMap<>();
        for (Entry entry : entries) {
            types.put(entry.typeId(), entry);
            objects.putIfAbsent(entry.objectType(), entry.signature());
        }
        byTypeId = Collections.unmodifiableMap(types);
        byObjectType = Collections.unmodifiableMap(objects);
    }

    public static Optional<Il2CppDelegateSignatureCatalog> fromScript(
            ScriptMethodReader.ScriptData script) throws IOException {
        if (script.delegateSignatures().isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(restored(script.delegateSignatures().orElseThrow().stream()
                .map(row -> new Entry(row.typeId(), row.objectType(), row.signature()))
                .toList()));
    }

    static Il2CppDelegateSignatureCatalog restored(List<Entry> source) throws IOException {
        Map<Integer, Entry> types = new LinkedHashMap<>();
        Map<String, String> objects = new LinkedHashMap<>();
        for (Entry entry : source) {
            validate(entry);
            Entry previousType = types.putIfAbsent(entry.typeId(), entry);
            if (previousType != null && !previousType.equals(entry)) {
                throw new IOException("conflicting delegate TypeId entries");
            }
            String previousSignature = objects.putIfAbsent(
                    entry.objectType(), entry.signature());
            if (previousSignature != null && !previousSignature.equals(entry.signature())) {
                throw new IOException("conflicting delegate object type entries");
            }
        }

        List<Entry> entries = new ArrayList<>(types.values());
        entries.sort(Comparator.comparingInt(Entry::typeId)
                .thenComparing(Entry::objectType));
        return new Il2CppDelegateSignatureCatalog(entries);
    }

    public List<Entry> entries() {
        return entries;
    }

    public Optional<Entry> forTypeId(int typeId) {
        return Optional.ofNullable(byTypeId.get(typeId));
    }

    public Optional<String> forObjectType(String objectType) {
        return Optional.ofNullable(byObjectType.get(objectType));
    }

    private static void validate(Entry entry) throws IOException {
        if (entry == null || entry.typeId() < 0 || invalid(entry.objectType()) ||
                invalid(entry.signature())) {
            throw new IOException("invalid delegate-signature catalogue entry");
        }
    }

    private static boolean invalid(String value) {
        return value == null || value.isBlank() ||
                value.codePoints().anyMatch(Character::isISOControl);
    }

    public record Entry(int typeId, String objectType, String signature) {
    }
}
