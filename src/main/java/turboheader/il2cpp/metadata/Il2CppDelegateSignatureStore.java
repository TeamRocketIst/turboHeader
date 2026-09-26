package turboheader.il2cpp.metadata;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

import ghidra.program.model.listing.Program;

/** Persists validated delegate signatures in the Ghidra program database. */
public final class Il2CppDelegateSignatureStore {
    private static final String OPTIONS = "TurboHeader IL2CPP";
    private static final String CATALOGUE = "Delegate Signature Catalogue";

    private Il2CppDelegateSignatureStore() {
    }

    public static void replace(Program program,
            Optional<Il2CppDelegateSignatureCatalog> catalog) {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(catalog, "catalog");
        int transaction = program.startTransaction("TurboHeader delegate signature catalogue");
        boolean commit = false;
        try {
            var options = program.getOptions(OPTIONS);
            if (catalog.isPresent()) {
                options.setByteArray(CATALOGUE,
                        Il2CppDelegateSignatureCodec.encode(catalog.orElseThrow()));
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

    public static Optional<Il2CppDelegateSignatureCatalog> read(Program program)
            throws IOException {
        Objects.requireNonNull(program, "program");
        byte[] encoded = program.getOptions(OPTIONS).getByteArray(CATALOGUE, null);
        if (encoded == null) {
            return Optional.empty();
        }
        return Optional.of(Il2CppDelegateSignatureCodec.decode(encoded));
    }
}
