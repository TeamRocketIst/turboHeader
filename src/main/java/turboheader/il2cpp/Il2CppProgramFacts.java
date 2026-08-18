package turboheader.il2cpp;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.exception.DuplicateNameException;

/** Persistent IL2CPP facts shared by import and analysis inside one Ghidra program. */
public final class Il2CppProgramFacts {
    private static final String MANAGED_METHODS = "TurboHeader.IL2CPP.ManagedMethods";
    private static final String RUNTIME_METADATA_PROBES =
            "TurboHeader.IL2CPP.RuntimeMetadataProbes";
    private static final String RUNTIME_METADATA_SLOTS =
            "TurboHeader.IL2CPP.RuntimeMetadataSlots";
    private static final String METHOD_METADATA_NAMES =
            "TurboHeader.IL2CPP.MethodMetadataNames";
    private static final String EXCEPTION_MESSAGE_GETTER =
            "System.Exception$$get_Message";

    private Il2CppProgramFacts() {
    }

    public static void replaceManagedMethods(Program program,
            List<ScriptMethodReader.ScriptMethod> methods) {
        AddressSet addresses = new AddressSet();
        AddressSet probes = new AddressSet();
        Address imageBase = program.getImageBase();
        for (ScriptMethodReader.ScriptMethod method : methods) {
            Address address = imageBase.add(method.address());
            if (program.getMemory().contains(address)) {
                addresses.add(address);
                if (EXCEPTION_MESSAGE_GETTER.equals(method.name())) {
                    probes.add(address);
                }
            }
        }
        addressMap(program, MANAGED_METHODS).set(addresses);
        addressMap(program, RUNTIME_METADATA_PROBES).set(probes);
    }

    public static RegistrationStats replaceManagedMethodOffsets(Program program,
            Collection<Long> methodOffsets, Collection<Long> runtimeMetadataProbeOffsets) {
        if (program == null || methodOffsets == null || runtimeMetadataProbeOffsets == null) {
            throw new IllegalArgumentException("program and managed-method collections are required");
        }

        AddressSet methods = checkedOffsets(program, methodOffsets, "managed method");
        AddressSet probes = checkedOffsets(program, runtimeMetadataProbeOffsets,
                "runtime metadata probe");
        if (!methods.contains(probes)) {
            throw new IllegalArgumentException(
                    "runtime metadata probes must also be managed methods");
        }

        addressMap(program, MANAGED_METHODS).set(methods);
        addressMap(program, RUNTIME_METADATA_PROBES).set(probes);
        return new RegistrationStats(methodOffsets.size(), methods.getNumAddresses(),
                runtimeMetadataProbeOffsets.size(), probes.getNumAddresses());
    }

    public static Set<Long> readManagedMethods(Program program) {
        AddressSetPropertyMap map = program.getAddressSetPropertyMap(MANAGED_METHODS);
        if (map == null) {
            return Set.of();
        }
        Set<Long> result = new HashSet<>();
        Address imageBase = program.getImageBase();
        var addresses = map.getAddresses();
        while (addresses.hasNext()) {
            result.add(addresses.next().subtract(imageBase));
        }
        return result;
    }

    public static Set<Address> readRuntimeMetadataProbes(Program program) {
        return readMappedAddresses(program, RUNTIME_METADATA_PROBES);
    }

    public static void replaceRuntimeMetadataSlots(Program program, Set<Address> slots) {
        AddressSet addresses = new AddressSet();
        for (Address slot : slots) {
            if (program.getMemory().contains(slot)) {
                addresses.add(slot);
            }
        }
        addressMap(program, RUNTIME_METADATA_SLOTS).set(addresses);
    }

    public static Set<Address> readRuntimeMetadataSlots(Program program) {
        return readMappedAddresses(program, RUNTIME_METADATA_SLOTS);
    }

    public static void replaceMethodMetadataNames(Program program,
            Map<Address, String> names) {
        StringPropertyMap map = stringMap(program, METHOD_METADATA_NAMES);
        map.clear();
        for (var entry : names.entrySet()) {
            map.add(entry.getKey(), entry.getValue());
        }
    }

    public static Map<Address, String> readMethodMetadataNames(Program program) {
        var manager = program.getUsrPropertyManager();
        StringPropertyMap map = manager.getStringPropertyMap(METHOD_METADATA_NAMES);
        if (map == null) {
            return Map.of();
        }
        Map<Address, String> result = new HashMap<>();
        var addresses = map.getPropertyIterator();
        while (addresses.hasNext()) {
            Address address = addresses.next();
            result.put(address, map.getString(address));
        }
        return Map.copyOf(result);
    }

    private static Set<Address> readMappedAddresses(Program program, String name) {
        AddressSetPropertyMap map = program.getAddressSetPropertyMap(name);
        if (map == null) {
            return Set.of();
        }
        Set<Address> result = new HashSet<>();
        var addresses = map.getAddresses();
        while (addresses.hasNext()) {
            result.add(addresses.next());
        }
        return Set.copyOf(result);
    }

    private static AddressSet checkedOffsets(Program program, Collection<Long> offsets,
            String description) {
        AddressSet addresses = new AddressSet();
        Address imageBase = program.getImageBase();
        for (Long boxedOffset : offsets) {
            if (boxedOffset == null || boxedOffset < 0) {
                throw new IllegalArgumentException("invalid " + description + " offset");
            }
            Address address;
            try {
                address = imageBase.add(boxedOffset);
            }
            catch (RuntimeException e) {
                throw new IllegalArgumentException(
                        "invalid " + description + " offset 0x" +
                        Long.toUnsignedString(boxedOffset, 16), e);
            }
            var block = program.getMemory().getBlock(address);
            if (block == null || !block.isExecute()) {
                throw new IllegalArgumentException(
                        description + " offset 0x" + Long.toUnsignedString(boxedOffset, 16) +
                        " is not in executable program memory");
            }
            addresses.add(address);
        }
        return addresses;
    }

    private static AddressSetPropertyMap addressMap(Program program, String name) {
        AddressSetPropertyMap existing = program.getAddressSetPropertyMap(name);
        if (existing != null) {
            return existing;
        }
        try {
            return program.createAddressSetPropertyMap(name);
        }
        catch (DuplicateNameException e) {
            AddressSetPropertyMap raced = program.getAddressSetPropertyMap(name);
            if (raced != null) {
                return raced;
            }
            throw new IllegalStateException("Could not create IL2CPP managed-method map", e);
        }
    }

    private static StringPropertyMap stringMap(Program program, String name) {
        var manager = program.getUsrPropertyManager();
        StringPropertyMap existing = manager.getStringPropertyMap(name);
        if (existing != null) {
            return existing;
        }
        try {
            return manager.createStringPropertyMap(name);
        }
        catch (DuplicateNameException e) {
            StringPropertyMap raced = manager.getStringPropertyMap(name);
            if (raced != null) {
                return raced;
            }
            throw new IllegalStateException("Could not create IL2CPP string property map", e);
        }
    }

    public record RegistrationStats(int methodEntries, long managedMethods,
            int probeEntries, long runtimeMetadataProbes) {
    }

}
