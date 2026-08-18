package turboheader.il2cpp;

import java.util.Locale;

/** Builds deterministic labels for IL2CPP method-metadata objects and their pointer slots. */
public final class Il2CppMethodMetadataLabels {
    static final int MAX_LABEL_LENGTH = 2000;

    private static final String TARGET_PREFIX = "Method_";
    private static final String POINTER_PREFIX = "PTR_";
    private static final String TRUNCATION_MARKER = "_truncated";

    private Il2CppMethodMetadataLabels() {
    }

    public static String target(long mappedAddress, String managedName) {
        return label(TARGET_PREFIX, mappedAddress, managedName);
    }

    public static String pointer(long mappedAddress, String managedName) {
        return label(POINTER_PREFIX + TARGET_PREFIX, mappedAddress, managedName);
    }

    public static String comment(String managedName) {
        if (managedName == null) {
            throw new IllegalArgumentException("managed name must not be null");
        }
        return "IL2CPP method metadata: " + managedName;
    }

    private static String label(String prefix, long mappedAddress, String managedName) {
        if (mappedAddress < 0) {
            throw new IllegalArgumentException("mapped address must not be negative");
        }
        if (managedName == null || managedName.isBlank()) {
            throw new IllegalArgumentException("managed name must not be blank");
        }

        String address = formatAddress(mappedAddress);
        int payloadBudget = MAX_LABEL_LENGTH - prefix.length() - address.length() - 1;
        String payload = sanitize(managedName, payloadBudget);
        return prefix + payload + '_' + address;
    }

    private static String sanitize(String value, int budget) {
        StringBuilder result = new StringBuilder(Math.min(value.length(), budget));
        boolean previousSeparator = false;
        int offset = 0;
        for (; offset < value.length();) {
            int codePoint = value.codePointAt(offset);
            boolean valid = codePoint == '$' || codePoint == '_' ||
                    Character.isLetterOrDigit(codePoint);
            if (valid) {
                int required = Character.charCount(codePoint);
                if (result.length() + required > budget) {
                    break;
                }
                result.appendCodePoint(codePoint);
                previousSeparator = false;
            }
            else if (!previousSeparator && !result.isEmpty()) {
                if (result.length() + 1 > budget) {
                    break;
                }
                result.append('_');
                previousSeparator = true;
            }
            offset += Character.charCount(codePoint);
        }
        while (!result.isEmpty() && result.charAt(result.length() - 1) == '_') {
            result.setLength(result.length() - 1);
        }
        if (result.isEmpty()) {
            result.append("unnamed");
        }
        if (offset < value.length() &&
                result.length() + TRUNCATION_MARKER.length() <= budget) {
            result.append(TRUNCATION_MARKER);
        }
        return result.toString();
    }

    private static String formatAddress(long address) {
        String hexadecimal = Long.toHexString(address).toLowerCase(Locale.ROOT);
        return "0".repeat(Math.max(0, 8 - hexadecimal.length())) + hexadecimal;
    }
}
