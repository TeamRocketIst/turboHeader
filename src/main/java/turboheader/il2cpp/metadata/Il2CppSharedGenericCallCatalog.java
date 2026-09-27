package turboheader.il2cpp.metadata;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Physical shared-generic call signatures keyed by MethodInfo identity. */
public final class Il2CppSharedGenericCallCatalog {
    private final List<Entry> entries;
    private final Map<Long, Entry> byMethodInfoAddress;
    private final Map<Long, List<Entry>> byMethodAddress;

    private Il2CppSharedGenericCallCatalog(List<Entry> entries) {
        this.entries = List.copyOf(entries);
        Map<Long, Entry> methodInfo = new LinkedHashMap<>();
        Map<Long, List<Entry>> methods = new LinkedHashMap<>();
        for (Entry entry : entries) {
            methodInfo.put(entry.methodInfoAddress(), entry);
            methods.computeIfAbsent(entry.methodAddress(), ignored -> new ArrayList<>())
                    .add(entry);
        }
        byMethodInfoAddress = Collections.unmodifiableMap(methodInfo);
        Map<Long, List<Entry>> frozen = new LinkedHashMap<>();
        for (var entry : methods.entrySet()) {
            frozen.put(entry.getKey(), List.copyOf(entry.getValue()));
        }
        byMethodAddress = Collections.unmodifiableMap(frozen);
    }

    public static Optional<Il2CppSharedGenericCallCatalog> fromScript(
            ScriptMethodReader.ScriptData script) throws IOException {
        if (script.sharedGenericCalls().isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(restored(script.sharedGenericCalls().orElseThrow().stream()
                .map(row -> new Entry(row.methodInfoAddress(), row.methodAddress(),
                        row.signature()))
                .toList()));
    }

    static Il2CppSharedGenericCallCatalog restored(List<Entry> source) throws IOException {
        Map<Long, Entry> methodInfo = new LinkedHashMap<>();
        for (Entry entry : source) {
            validate(entry);
            Entry previous = methodInfo.putIfAbsent(entry.methodInfoAddress(), entry);
            if (previous != null && !previous.equals(entry)) {
                throw new IOException("conflicting shared-generic MethodInfo entries");
            }
        }
        List<Entry> entries = new ArrayList<>(methodInfo.values());
        entries.sort(Comparator.comparingLong(Entry::methodInfoAddress));
        return new Il2CppSharedGenericCallCatalog(entries);
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

    private static void validate(Entry entry) throws IOException {
        if (entry == null || entry.methodInfoAddress() <= 0 ||
                entry.methodAddress() <= 0 || invalid(entry.signature())) {
            throw new IOException("invalid shared-generic call catalogue entry");
        }
        try {
            SharedGenericCallSignature.parse(entry.signature());
        }
        catch (IllegalArgumentException e) {
            throw new IOException("invalid shared-generic physical signature", e);
        }
    }

    private static boolean invalid(String value) {
        return value == null || value.isBlank() ||
                value.codePoints().anyMatch(Character::isISOControl);
    }

    public record Entry(long methodInfoAddress, long methodAddress, String signature) {
    }
}
