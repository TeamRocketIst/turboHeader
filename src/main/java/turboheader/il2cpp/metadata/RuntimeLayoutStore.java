package turboheader.il2cpp.metadata;

import java.io.IOException;
import java.util.Optional;

import ghidra.framework.options.OptionType;
import ghidra.program.model.listing.Program;

/** Carries the layout decision across the import/export process boundary. */
public final class RuntimeLayoutStore {
    private static final String OPTIONS = "TurboHeader IL2CPP";
    private static final String STATUS = "Runtime Layout Status";
    private static final String POINTER_SIZE = "Runtime Layout Pointer Size";
    private static final String PROFILE = "Runtime Layout Profile";

    private RuntimeLayoutStore() {
    }

    public static void replace(Program program, Optional<RuntimeLayoutInfo> layout) {
        int transaction = program.startTransaction("TurboHeader runtime layout confidence");
        boolean commit = false;
        try {
            var options = program.getOptions(OPTIONS);
            if (layout.isPresent()) {
                var info = layout.orElseThrow();
                options.setString(STATUS, info.status());
                options.setInt(POINTER_SIZE, info.pointerSize());
                options.setString(PROFILE, info.profile());
            }
            else {
                options.removeOption(STATUS);
                options.removeOption(POINTER_SIZE);
                options.removeOption(PROFILE);
            }
            commit = true;
        }
        finally {
            program.endTransaction(transaction, commit);
        }
    }

    public static boolean allowsProofs(Program program) throws IOException {
        var layout = read(program);
        return layout.isEmpty() || (layout.orElseThrow().runtimeFieldsVerified() &&
                layout.orElseThrow().pointerSize() == program.getDefaultPointerSize());
    }

    public static boolean merge(Program program, Optional<RuntimeLayoutInfo> incoming) throws IOException {
        var current = read(program);
        if (incoming.isPresent() && current.isPresent() && !incoming.equals(current)) {
            throw new IOException("conflicting runtime layout confidence");
        }
        if (incoming.isPresent() && current.isEmpty()) {
            replace(program, incoming);
            return true;
        }
        return false;
    }

    private static Optional<RuntimeLayoutInfo> read(Program program) throws IOException {
        var options = program.getOptions(OPTIONS);
        if (!options.contains(STATUS) && !options.contains(POINTER_SIZE) && !options.contains(PROFILE)) return Optional.empty();
        if (options.getType(STATUS) != OptionType.STRING_TYPE ||
                options.getType(POINTER_SIZE) != OptionType.INT_TYPE || options.getType(PROFILE) != OptionType.STRING_TYPE) {
            throw new IOException("invalid stored runtime layout option types");
        }
        String status = options.getString(STATUS, null);
        int pointerSize = options.getInt(POINTER_SIZE, 0);
        try {
            var info = new RuntimeLayoutInfo(status, pointerSize, "verified".equals(status), options.getString(PROFILE, null));
            return Optional.of(info);
        }
        catch (IllegalArgumentException e) {
            throw new IOException("invalid stored runtime layout confidence", e);
        }
    }
}
