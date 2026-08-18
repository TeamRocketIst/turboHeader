package turboheader.il2cpp;

import java.util.Locale;

/** Produces compact helper names with a stable mapped-address suffix. */
final class Il2CppHelperNames {
    private static final int MINIMUM_ADDRESS_DIGITS = 8;

    private Il2CppHelperNames() {
    }

    static String mappedName(Il2CppHelperKind kind, long offset) {
        String hexadecimal = Long.toUnsignedString(offset, 16).toLowerCase(Locale.ROOT);
        return kind.stem() + "_" +
                "0".repeat(Math.max(0, MINIMUM_ADDRESS_DIGITS - hexadecimal.length())) +
                hexadecimal;
    }
}
