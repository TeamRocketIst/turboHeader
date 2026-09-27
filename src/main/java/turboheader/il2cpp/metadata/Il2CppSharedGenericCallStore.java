package turboheader.il2cpp.metadata;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

import ghidra.program.model.listing.Program;

/** Persists validated shared-generic call facts in the Ghidra program. */
public final class Il2CppSharedGenericCallStore {
    private static final String OPTIONS = "TurboHeader IL2CPP";
    private static final String CATALOGUE = "Shared Generic Call Catalogue";

    private Il2CppSharedGenericCallStore() {
    }

    public static void replace(Program program,
            Optional<Il2CppSharedGenericCallCatalog> catalog) {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(catalog, "catalog");
        int transaction = program.startTransaction("TurboHeader shared generic catalogue");
        boolean commit = false;
        try {
            var options = program.getOptions(OPTIONS);
            if (catalog.isPresent()) {
                options.setByteArray(CATALOGUE,
                        Il2CppSharedGenericCallCodec.encode(catalog.orElseThrow()));
            }
            else {
                options.removeOption(CATALOGUE);
            }
            commit = true;
        }
        finally {
            program.endTransaction(transaction, commit);
        }
    }

    public static Optional<Il2CppSharedGenericCallCatalog> read(Program program)
            throws IOException {
        Objects.requireNonNull(program, "program");
        byte[] encoded = program.getOptions(OPTIONS).getByteArray(CATALOGUE, null);
        if (encoded == null) {
            return Optional.empty();
        }
        return Optional.of(Il2CppSharedGenericCallCodec.decode(encoded));
    }
}
