package turboheader.il2cpp.metadata;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

import ghidra.program.model.listing.Program;
import ghidra.framework.options.OptionType;

public final class Il2CppReferenceGenericCallStore {
    private static final String OPTIONS = "TurboHeader IL2CPP";
    private static final String CATALOGUE = "Reference Generic Call Catalogue";

    private Il2CppReferenceGenericCallStore() {
    }

    public static void replace(Program program,
            Optional<Il2CppReferenceGenericCallCatalog> catalog) throws IOException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(catalog, "catalog");
        byte[] encoded = catalog.isPresent()
                ? Il2CppReferenceGenericCallCodec.encode(catalog.orElseThrow()) : null;
        int transaction = program.startTransaction("TurboHeader reference generic catalogue");
        boolean commit = false;
        try {
            var options = program.getOptions(OPTIONS);
            if (encoded == null) {
                options.removeOption(CATALOGUE);
            }
            else {
                options.setByteArray(CATALOGUE, encoded);
            }
            commit = true;
        }
        finally {
            program.endTransaction(transaction, commit);
        }
    }

    public static Optional<Il2CppReferenceGenericCallCatalog> read(Program program)
            throws IOException {
        Objects.requireNonNull(program, "program");
        var options = program.getOptions(OPTIONS);
        if (!options.contains(CATALOGUE)) {
            return Optional.empty();
        }
        if (options.getType(CATALOGUE) != OptionType.BYTE_ARRAY_TYPE) {
            throw new IOException("invalid stored reference-generic option type");
        }
        return Optional.of(Il2CppReferenceGenericCallCodec.decode(options.getByteArray(CATALOGUE, null)));
    }
}
