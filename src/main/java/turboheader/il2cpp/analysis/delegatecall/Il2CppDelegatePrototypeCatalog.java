package turboheader.il2cpp.analysis.delegatecall;

import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import ghidra.program.model.listing.Program;
import turboheader.il2cpp.metadata.Il2CppDelegateSignatureStore;

/** Parsed delegate prototypes loaded from the validated program catalogue. */
public final class Il2CppDelegatePrototypeCatalog {
    private final Map<Integer, DelegateCallPrototype> prototypes;
    private final Map<String, DelegateCallPrototype> prototypesByObjectType;

    private Il2CppDelegatePrototypeCatalog(Map<Integer, DelegateCallPrototype> prototypes) {
        this.prototypes = Collections.unmodifiableMap(new LinkedHashMap<>(prototypes));
        Map<String, DelegateCallPrototype> byObjectType = new LinkedHashMap<>();
        for (DelegateCallPrototype prototype : prototypes.values()) {
            DelegateCallPrototype previous = byObjectType.putIfAbsent(
                    prototype.objectType(), prototype);
            if (previous != null && !previous.signature().equals(prototype.signature())) {
                throw new IllegalArgumentException("conflicting delegate object type: " +
                        prototype.objectType());
            }
        }
        prototypesByObjectType = Collections.unmodifiableMap(byObjectType);
    }

    public static Optional<Il2CppDelegatePrototypeCatalog> read(Program program)
            throws IOException {
        var stored = Il2CppDelegateSignatureStore.read(program);
        if (stored.isEmpty()) {
            return Optional.empty();
        }

        Map<Integer, DelegateCallPrototype> prototypes = new LinkedHashMap<>();
        for (var entry : stored.orElseThrow().entries()) {
            DelegateCallPrototype prototype;
            try {
                prototype = DelegateCallPrototype.parse(entry.typeId(),
                        entry.objectType(), entry.signature());
            }
            catch (IllegalArgumentException e) {
                throw new IOException("invalid delegate signature for TypeId " +
                        entry.typeId(), e);
            }
            prototypes.put(entry.typeId(), prototype);
        }
        try {
            return Optional.of(new Il2CppDelegatePrototypeCatalog(prototypes));
        }
        catch (IllegalArgumentException e) {
            throw new IOException("invalid delegate signature catalogue", e);
        }
    }

    public int size() {
        return prototypes.size();
    }

    public Optional<DelegateCallPrototype> forTypeId(int typeId) {
        return Optional.ofNullable(prototypes.get(typeId));
    }

    public Optional<DelegateCallPrototype> forObjectType(String objectType) {
        return Optional.ofNullable(prototypesByObjectType.get(objectType));
    }
}
