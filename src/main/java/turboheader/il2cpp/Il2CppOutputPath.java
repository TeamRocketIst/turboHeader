package turboheader.il2cpp;

import java.io.IOException;
import java.nio.file.Path;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public final class Il2CppOutputPath {
    private static final String INVALID_FILENAME_CHARS = "<>:\"\\|?*";
    private static final Set<String> WINDOWS_RESERVED_NAMES = Set.of(
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
            "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
            "LPT6", "LPT7", "LPT8", "LPT9", "CONIN$", "CONOUT$");

    private Il2CppOutputPath() {
    }

    public static Path forClass(Il2CppClassCatalog.ClassEntry entry) {
        Objects.requireNonNull(entry, "entry");
        List<String> parts = new ArrayList<>();
        parts.add(sanitize(entry.assembly()));

        String source = entry.relativeSource();
        String stem = source.substring(0, source.length() - 3) + ".cpp";
        for (String part : stem.split("/", -1)) {
            if (part.isEmpty() || part.equals(".") || part.equals("..")) {
                throw new IllegalArgumentException("invalid class output path");
            }
            parts.add(sanitize(part));
        }

        Path result = Path.of(parts.get(0));
        for (int index = 1; index < parts.size(); index++) {
            result = result.resolve(parts.get(index));
        }
        return result;
    }

    public static Map<Il2CppClassCatalog.ClassEntry, Path> forClasses(
            List<Il2CppClassCatalog.ClassEntry> classes) throws IOException {
        Objects.requireNonNull(classes, "classes");
        Map<Il2CppClassCatalog.ClassEntry, Path> outputs = new LinkedHashMap<>();
        Map<String, Il2CppClassCatalog.ClassEntry> collisionKeys = new LinkedHashMap<>();
        for (var entry : classes) {
            Path output = forClass(entry);
            String key = Normalizer.normalize(portable(output), Normalizer.Form.NFC)
                    .toLowerCase(Locale.ROOT);
            var previous = collisionKeys.putIfAbsent(key, entry);
            if (previous != null) {
                throw new IOException("class output path collision: " + previous.displayName() +
                        " and " + entry.displayName());
            }
            outputs.put(entry, output);
        }
        return Collections.unmodifiableMap(outputs);
    }

    static String sanitize(String value) {
        if (value.isEmpty()) {
            throw new IllegalArgumentException("output path component must not be empty");
        }
        StringBuilder result = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character < 0x20 || character == '/' ||
                    INVALID_FILENAME_CHARS.indexOf(character) >= 0) {
                result.append('_');
            }
            else {
                result.append(character);
            }
        }
        while (!result.isEmpty()) {
            char last = result.charAt(result.length() - 1);
            if (last != '.' && last != ' ') {
                break;
            }
            result.setCharAt(result.length() - 1, '_');
        }

        String sanitized = result.toString();
        int extension = sanitized.indexOf('.');
        String stem = extension < 0 ? sanitized : sanitized.substring(0, extension);
        if (WINDOWS_RESERVED_NAMES.contains(stem.toUpperCase(Locale.ROOT))) {
            return "_" + sanitized;
        }
        return sanitized;
    }

    private static String portable(Path path) {
        return path.toString().replace('\\', '/');
    }
}
