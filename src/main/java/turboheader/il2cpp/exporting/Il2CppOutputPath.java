package turboheader.il2cpp.exporting;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public final class Il2CppOutputPath {
    private static final String INVALID_FILENAME_CHARS = "<>:\"\\|?*";
    private static final int SUFFIX_BYTES = 8;
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
        List<PathCandidate> candidates = new ArrayList<>(classes.size());
        Map<String, List<PathCandidate>> groups = new LinkedHashMap<>();
        Set<ClassIdentity> identities = new HashSet<>();
        for (var entry : classes) {
            ClassIdentity identity = new ClassIdentity(entry.assembly(), entry.relativeSource());
            if (!identities.add(identity)) {
                throw new IOException("duplicate class identity: " + entry.displayName());
            }
            Path output = forClass(entry);
            PathCandidate candidate = new PathCandidate(entry, output);
            candidates.add(candidate);
            groups.computeIfAbsent(collisionKey(output), unused -> new ArrayList<>())
                    .add(candidate);
        }

        Map<Il2CppClassCatalog.ClassEntry, Path> outputs = new LinkedHashMap<>();
        Map<String, Il2CppClassCatalog.ClassEntry> finalKeys = new LinkedHashMap<>();
        for (PathCandidate candidate : candidates) {
            List<PathCandidate> group = groups.get(collisionKey(candidate.path()));
            Path output = group.size() == 1
                    ? candidate.path()
                    : appendSuffix(candidate.path(), stableSuffix(candidate.entry()));
            var previous = finalKeys.putIfAbsent(collisionKey(output), candidate.entry());
            if (previous != null) {
                throw new IOException("class output path collision: " + previous.displayName() +
                        " and " + candidate.entry().displayName());
            }
            outputs.put(candidate.entry(), output);
        }
        return Collections.unmodifiableMap(outputs);
    }

    private static Path appendSuffix(Path path, String suffix) {
        String fileName = path.getFileName().toString();
        int extension = fileName.lastIndexOf('.');
        if (extension <= 0) {
            throw new IllegalArgumentException("class output path has no extension");
        }
        String resolved = fileName.substring(0, extension) + "__" + suffix +
                fileName.substring(extension);
        Path parent = path.getParent();
        return parent == null ? Path.of(resolved) : parent.resolve(resolved);
    }

    private static String stableSuffix(Il2CppClassCatalog.ClassEntry entry) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(entry.assembly().getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);
            byte[] value = digest.digest(entry.relativeSource().getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(value, 0, SUFFIX_BYTES);
        }
        catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 is unavailable", error);
        }
    }

    private static String collisionKey(Path path) {
        return Normalizer.normalize(portable(path), Normalizer.Form.NFC)
                .toLowerCase(Locale.ROOT);
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

    private record PathCandidate(Il2CppClassCatalog.ClassEntry entry, Path path) {
    }

    private record ClassIdentity(String assembly, String relativeSource) {
    }
}
