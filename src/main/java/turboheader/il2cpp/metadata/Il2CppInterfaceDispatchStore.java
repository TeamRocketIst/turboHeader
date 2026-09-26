package turboheader.il2cpp.metadata;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

import ghidra.program.model.listing.Program;

/** Persists the validated interface dispatch catalogue in the Ghidra program database. */
public final class Il2CppInterfaceDispatchStore {
    private static final String OPTIONS = "TurboHeader IL2CPP";
    private static final String CATALOGUE = "Interface Dispatch Catalogue";

    private Il2CppInterfaceDispatchStore() {
    }

    public static void replace(Program program,
            Optional<Il2CppInterfaceDispatchCatalog> catalog) {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(catalog, "catalog");
        int transaction = program.startTransaction("TurboHeader interface dispatch catalogue");
        boolean commit = false;
        try {
            var options = program.getOptions(OPTIONS);
            if (catalog.isPresent()) {
                options.setByteArray(CATALOGUE,
                        Il2CppInterfaceDispatchCodec.encode(catalog.orElseThrow()));
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

    public static Optional<Il2CppInterfaceDispatchCatalog> read(Program program)
            throws IOException {
        Objects.requireNonNull(program, "program");
        byte[] encoded = program.getOptions(OPTIONS).getByteArray(CATALOGUE, null);
        if (encoded == null) {
            return Optional.empty();
        }
        return Optional.of(Il2CppInterfaceDispatchCodec.decode(encoded));
    }
}
