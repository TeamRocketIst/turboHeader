package turboheader.il2cpp.metadata;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;

/** Exact interface dispatch facts validated against the other script.json tables. */
public final class Il2CppInterfaceDispatchCatalog {
    private static final int MAX_TYPE_IDENTITIES = 1_000_000;

    private final Map<Long, Integer> typeIdsByMetadataAddress;
    private final Map<DispatchKey, Long> methodAddresses;

    private Il2CppInterfaceDispatchCatalog(Map<Long, Integer> typeIdsByMetadataAddress,
            Map<DispatchKey, Long> methodAddresses) {
        this.typeIdsByMetadataAddress = immutableOrderedTypes(typeIdsByMetadataAddress);
        this.methodAddresses = immutableOrderedDispatch(methodAddresses);
    }

    public static Optional<Il2CppInterfaceDispatchCatalog> fromScript(
            ScriptMethodReader.ScriptData script) throws IOException {
        if (script.interfaceDispatch().isEmpty()) {
            return Optional.empty();
        }

        Map<Long, Integer> typeIds = collectTypeIds(script.metadata());
        Set<Integer> knownTypeIds = new HashSet<>(typeIds.values());
        Map<Long, ScriptMethodReader.ScriptMethod> methods = uniqueMethods(script.methods());
        Map<DispatchKey, Long> dispatch = new HashMap<>();

        for (var entry : script.interfaceDispatch().orElseThrow()) {
            if (!knownTypeIds.contains(entry.receiverTypeId()) ||
                    !knownTypeIds.contains(entry.interfaceTypeId())) {
                throw new IOException("interface-dispatch entry references an unknown TypeId");
            }
            var method = methods.get(entry.methodAddress());
            if (method == null) {
                throw new IOException(
                        "interface-dispatch target is absent or ambiguous in ScriptMethod");
            }
            if (!method.signature().equals(entry.signature())) {
                throw new IOException("interface-dispatch signature does not match ScriptMethod");
            }

            DispatchKey key = new DispatchKey(entry.receiverTypeId(), entry.interfaceTypeId(),
                    entry.interfaceSlot());
            Long previous = dispatch.putIfAbsent(key, entry.methodAddress());
            if (previous != null && previous.longValue() != entry.methodAddress()) {
                throw new IOException("conflicting interface-dispatch entries");
            }
        }

        return Optional.of(new Il2CppInterfaceDispatchCatalog(typeIds, dispatch));
    }

    static Il2CppInterfaceDispatchCatalog restored(Map<Long, Integer> typeIds,
            Map<DispatchKey, Long> methodAddresses) throws IOException {
        Set<Integer> knownTypeIds = new HashSet<>(typeIds.values());
        for (var entry : typeIds.entrySet()) {
            if (entry.getKey() < 0 || entry.getValue() < 0) {
                throw new IOException("invalid stored interface-dispatch type identity");
            }
        }
        for (var entry : methodAddresses.entrySet()) {
            DispatchKey key = entry.getKey();
            if (!knownTypeIds.contains(key.receiverTypeId()) ||
                    !knownTypeIds.contains(key.interfaceTypeId()) ||
                    entry.getValue() <= 0) {
                throw new IOException("invalid stored interface-dispatch entry");
            }
        }
        return new Il2CppInterfaceDispatchCatalog(typeIds, methodAddresses);
    }

    public Map<Long, Integer> typeIdsByMetadataAddress() {
        return typeIdsByMetadataAddress;
    }

    public Map<DispatchKey, Long> methodAddresses() {
        return methodAddresses;
    }

    public OptionalLong methodAddress(int receiverTypeId, int interfaceTypeId,
            int interfaceSlot) {
        Long address = methodAddresses.get(
                new DispatchKey(receiverTypeId, interfaceTypeId, interfaceSlot));
        return address == null ? OptionalLong.empty() : OptionalLong.of(address);
    }

    private static Map<Long, Integer> collectTypeIds(
            List<ScriptMethodReader.ScriptMetadata> metadata) throws IOException {
        Map<Long, Integer> result = new HashMap<>();
        for (var entry : metadata) {
            if (entry.typeId() == null) {
                continue;
            }
            if (result.size() == MAX_TYPE_IDENTITIES &&
                    !result.containsKey(entry.address())) {
                throw new IOException("too many ScriptMetadata TypeId entries");
            }
            Integer previous = result.putIfAbsent(entry.address(), entry.typeId());
            if (previous != null && previous.intValue() != entry.typeId()) {
                throw new IOException("conflicting ScriptMetadata TypeId entries");
            }
        }
        return result;
    }

    private static Map<Long, ScriptMethodReader.ScriptMethod> uniqueMethods(
            List<ScriptMethodReader.ScriptMethod> methods) {
        Map<Long, ScriptMethodReader.ScriptMethod> result = new HashMap<>();
        Set<Long> ambiguous = new HashSet<>();
        for (var method : methods) {
            if (ambiguous.contains(method.address())) {
                continue;
            }
            if (result.putIfAbsent(method.address(), method) == null) {
                continue;
            }
            result.remove(method.address());
            ambiguous.add(method.address());
        }
        return result;
    }

    private static Map<Long, Integer> immutableOrderedTypes(Map<Long, Integer> input) {
        List<Map.Entry<Long, Integer>> entries = new ArrayList<>(input.entrySet());
        entries.sort(Map.Entry.comparingByKey());
        Map<Long, Integer> result = new LinkedHashMap<>();
        for (var entry : entries) {
            result.put(entry.getKey(), entry.getValue());
        }
        return Collections.unmodifiableMap(result);
    }

    private static Map<DispatchKey, Long> immutableOrderedDispatch(
            Map<DispatchKey, Long> input) {
        List<Map.Entry<DispatchKey, Long>> entries = new ArrayList<>(input.entrySet());
        entries.sort(Map.Entry.comparingByKey(Comparator.naturalOrder()));
        Map<DispatchKey, Long> result = new LinkedHashMap<>();
        for (var entry : entries) {
            result.put(entry.getKey(), entry.getValue());
        }
        return Collections.unmodifiableMap(result);
    }

    public record DispatchKey(int receiverTypeId, int interfaceTypeId, int interfaceSlot)
            implements Comparable<DispatchKey> {
        public DispatchKey {
            if (receiverTypeId < 0 || interfaceTypeId < 0 || interfaceSlot < 0) {
                throw new IllegalArgumentException("interface-dispatch key must not be negative");
            }
        }

        @Override
        public int compareTo(DispatchKey other) {
            int receiver = Integer.compare(receiverTypeId, other.receiverTypeId);
            if (receiver != 0) {
                return receiver;
            }
            int interfaceType = Integer.compare(interfaceTypeId, other.interfaceTypeId);
            if (interfaceType != 0) {
                return interfaceType;
            }
            return Integer.compare(interfaceSlot, other.interfaceSlot);
        }
    }
}
