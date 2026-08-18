package turboheader.il2cpp;

import java.util.Locale;

/** Builds bounded, deterministic labels and comments for IL2CPP string literals. */
public final class Il2CppStringLabels {
    static final int MAX_LABEL_LENGTH = 2000;
    static final int MAX_COMMENT_LENGTH = 4096;

    private static final String LABEL_PREFIX = "PTR_str_";
    private static final String TRUNCATION_MARKER = "...";
    private static final String COMMENT_PREFIX = "IL2CPP string: \"";

    private Il2CppStringLabels() {
    }

    /**
     * Builds a label containing exactly one mapped Ghidra address. The payload is
     * truncated only between complete escaped code points.
     */
    public static String label(long mappedAddress, String value) {
        if (mappedAddress < 0) {
            throw new IllegalArgumentException("mapped address must not be negative");
        }
        if (value == null) {
            throw new IllegalArgumentException("string value must not be null");
        }

        String address = formatAddress(mappedAddress);
        int payloadBudget = MAX_LABEL_LENGTH - LABEL_PREFIX.length() - address.length() - 1;
        String payload = value.isEmpty() ? "empty" : boundedLabelPayload(value, payloadBudget);
        return LABEL_PREFIX + payload + '_' + address;
    }

    /** Builds a single-line, bounded comment containing the exact escaped literal. */
    public static String comment(String value) {
        if (value == null) {
            throw new IllegalArgumentException("string value must not be null");
        }

        int totalCodePoints = value.codePointCount(0, value.length());
        int escapedLength = escapedCommentLength(value);
        if (COMMENT_PREFIX.length() + escapedLength + 1 <= MAX_COMMENT_LENGTH) {
            StringBuilder result = new StringBuilder(COMMENT_PREFIX.length() + escapedLength + 1);
            result.append(COMMENT_PREFIX);
            appendCommentTokens(result, value, escapedLength);
            return result.append('"').toString();
        }

        String suffix = "\" [truncated; code points=" + totalCodePoints + ']';
        int payloadBudget = MAX_COMMENT_LENGTH - COMMENT_PREFIX.length() - suffix.length();
        StringBuilder result = new StringBuilder(MAX_COMMENT_LENGTH);
        result.append(COMMENT_PREFIX);
        appendCommentTokens(result, value, payloadBudget);
        return result.append(suffix).toString();
    }

    private static String boundedLabelPayload(String value, int budget) {
        int encodedLength = escapedLabelLength(value);
        boolean truncated = encodedLength > budget;
        int contentBudget = truncated ? budget - TRUNCATION_MARKER.length() : budget;
        StringBuilder result = new StringBuilder(Math.min(encodedLength, budget));
        for (int offset = 0; offset < value.length();) {
            int codePoint = value.codePointAt(offset);
            String token = labelToken(codePoint);
            if (result.length() + token.length() > contentBudget) {
                break;
            }
            result.append(token);
            offset += Character.charCount(codePoint);
        }
        if (truncated) {
            result.append(TRUNCATION_MARKER);
        }
        return result.toString();
    }

    private static int escapedLabelLength(String value) {
        int length = 0;
        for (int offset = 0; offset < value.length();) {
            int codePoint = value.codePointAt(offset);
            length += labelToken(codePoint).length();
            offset += Character.charCount(codePoint);
        }
        return length;
    }

    private static String labelToken(int codePoint) {
        if (codePoint >= 0x21 && codePoint <= 0x7e && codePoint != '\\') {
            return Character.toString(codePoint);
        }
        if (codePoint <= 0xff) {
            return String.format(Locale.ROOT, "\\x%02x", codePoint);
        }
        if (codePoint <= 0xffff) {
            return String.format(Locale.ROOT, "\\u%04x", codePoint);
        }
        return String.format(Locale.ROOT, "\\U%08x", codePoint);
    }

    private static int escapedCommentLength(String value) {
        int length = 0;
        for (int offset = 0; offset < value.length();) {
            int codePoint = value.codePointAt(offset);
            length += commentToken(codePoint).length();
            offset += Character.charCount(codePoint);
        }
        return length;
    }

    private static void appendCommentTokens(StringBuilder destination, String value, int budget) {
        int appended = 0;
        for (int offset = 0; offset < value.length();) {
            int codePoint = value.codePointAt(offset);
            String token = commentToken(codePoint);
            if (appended + token.length() > budget) {
                return;
            }
            destination.append(token);
            appended += token.length();
            offset += Character.charCount(codePoint);
        }
    }

    private static String commentToken(int codePoint) {
        return switch (codePoint) {
            case '\\' -> "\\\\";
            case '"' -> "\\\"";
            case '\n' -> "\\n";
            case '\r' -> "\\r";
            case '\t' -> "\\t";
            default -> {
                if (Character.isISOControl(codePoint) ||
                        Character.getType(codePoint) == Character.LINE_SEPARATOR ||
                        Character.getType(codePoint) == Character.PARAGRAPH_SEPARATOR) {
                    yield codePoint <= 0xffff
                            ? String.format(Locale.ROOT, "\\u%04x", codePoint)
                            : String.format(Locale.ROOT, "\\U%08x", codePoint);
                }
                yield Character.toString(codePoint);
            }
        };
    }

    private static String formatAddress(long address) {
        String hexadecimal = Long.toHexString(address).toLowerCase(Locale.ROOT);
        return "0".repeat(Math.max(0, 8 - hexadecimal.length())) + hexadecimal;
    }
}
