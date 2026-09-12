package turboheader.il2cpp.exporting;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;

final class PortableFilenameEncoder {
    static final int MAX_COMPONENT_LENGTH = 200;

    private static final int DIGEST_BYTES = 16;
    private static final char[] HEX_DIGITS = "0123456789ABCDEF".toCharArray();
    private static final String RESERVED_PREFIX = "~R";
    private static final String TRUNCATION_PREFIX = "~H";
    private static final Set<String> WINDOWS_RESERVED_NAMES = Set.of(
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
            "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
            "LPT6", "LPT7", "LPT8", "LPT9", "CONIN$", "CONOUT$");

    private PortableFilenameEncoder() {
    }

    static String encode(String value) {
        return encode(value, MAX_COMPONENT_LENGTH);
    }

    static String encode(String value, int maxLength) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("output path component must not be empty");
        }

        List<String> tokens = encodeTokens(value);
        if (isWindowsReserved(join(tokens))) {
            tokens.add(0, RESERVED_PREFIX);
        }
        return fit(tokens, value, maxLength);
    }

    private static List<String> encodeTokens(String value) {
        List<String> tokens = new ArrayList<>(value.length());
        for (int offset = 0; offset < value.length();) {
            char first = value.charAt(offset);
            if (Character.isSurrogate(first)) {
                boolean validPair = Character.isHighSurrogate(first) &&
                        offset + 1 < value.length() &&
                        Character.isLowSurrogate(value.charAt(offset + 1));
                if (!validPair) {
                    throw new IllegalArgumentException(
                            "output path component contains invalid Unicode");
                }
            }

            int codePoint = value.codePointAt(offset);
            int width = Character.charCount(codePoint);
            if (isAllowed(codePoint, offset, width, value.length())) {
                tokens.add(Character.toString(codePoint));
            }
            else {
                byte[] bytes = Character.toString(codePoint).getBytes(StandardCharsets.UTF_8);
                for (byte valueByte : bytes) {
                    int unsigned = Byte.toUnsignedInt(valueByte);
                    tokens.add("~" + HEX_DIGITS[unsigned >>> 4] + HEX_DIGITS[unsigned & 0xf]);
                }
            }
            offset += width;
        }
        return tokens;
    }

    private static boolean isAllowed(int codePoint, int offset, int width, int inputLength) {
        boolean letter = codePoint >= 'a' && codePoint <= 'z' ||
                codePoint >= 'A' && codePoint <= 'Z';
        boolean digit = codePoint >= '0' && codePoint <= '9';
        if (letter || digit) {
            return true;
        }
        if (codePoint == '_' || codePoint == '-' || codePoint == '`') {
            return true;
        }
        return codePoint == '.' && offset > 0 && offset + width < inputLength;
    }

    private static boolean isWindowsReserved(String value) {
        int extension = value.indexOf('.');
        String stem = extension < 0 ? value : value.substring(0, extension);
        return WINDOWS_RESERVED_NAMES.contains(stem.toUpperCase(Locale.ROOT));
    }

    private static String fit(List<String> tokens, String original, int maxLength) {
        String encoded = join(tokens);
        if (encoded.length() <= maxLength) {
            return encoded;
        }

        String suffix = TRUNCATION_PREFIX + digest(original);
        if (maxLength <= suffix.length()) {
            throw new IllegalArgumentException("output path component limit is too small");
        }
        int prefixLimit = maxLength - suffix.length();
        StringBuilder result = new StringBuilder(maxLength);
        for (String token : tokens) {
            if (result.length() + token.length() > prefixLimit) {
                break;
            }
            result.append(token);
        }
        return result.append(suffix).toString();
    }

    private static String digest(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().withUpperCase().formatHex(digest, 0, DIGEST_BYTES);
        }
        catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 is unavailable", error);
        }
    }

    private static String join(List<String> tokens) {
        StringBuilder result = new StringBuilder();
        for (String token : tokens) {
            result.append(token);
        }
        return result.toString();
    }
}
