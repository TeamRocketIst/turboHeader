package turboheader.il2cpp.exporting;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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

final class Il2CppOutputPathAllocator {
    private static final int SUFFIX_BYTES = 16;

    private Il2CppOutputPathAllocator() {
    }

    static Map<Il2CppClassCatalog.ClassEntry, Path> allocate(
            List<Il2CppClassCatalog.ClassEntry> classes) throws IOException {
        Objects.requireNonNull(classes, "classes");
        List<PathCandidate> candidates = createCandidates(classes);
        Set<PathCandidate> disambiguated = findCollisions(candidates);

        Map<Il2CppClassCatalog.ClassEntry, Path> outputs = new LinkedHashMap<>();
        Map<String, Il2CppClassCatalog.ClassEntry> finalFiles = new LinkedHashMap<>();
        Set<String> finalDirectories = new HashSet<>();
        for (PathCandidate candidate : candidates) {
            Path output = disambiguated.contains(candidate)
                    ? Il2CppOutputPath.withCollisionSuffix(
                            candidate.entry(), stableSuffix(candidate.entry()))
                    : candidate.path();
            validateFinalPath(output, candidate.entry(), finalFiles, finalDirectories);
            outputs.put(candidate.entry(), output);
        }
        return Collections.unmodifiableMap(outputs);
    }

    private static List<PathCandidate> createCandidates(
            List<Il2CppClassCatalog.ClassEntry> classes) throws IOException {
        List<PathCandidate> candidates = new ArrayList<>(classes.size());
        Set<ClassIdentity> identities = new HashSet<>();
        for (var entry : classes) {
            ClassIdentity identity = new ClassIdentity(entry.assembly(), entry.relativeSource());
            if (!identities.add(identity)) {
                throw new IOException("duplicate class identity: " + entry.displayName());
            }
            candidates.add(new PathCandidate(entry, Il2CppOutputPath.forClass(entry)));
        }
        return candidates;
    }

    private static Set<PathCandidate> findCollisions(List<PathCandidate> candidates) {
        Map<String, List<PathCandidate>> filesByPath = new LinkedHashMap<>();
        for (PathCandidate candidate : candidates) {
            filesByPath.computeIfAbsent(collisionKey(candidate.path()), unused -> new ArrayList<>())
                    .add(candidate);
        }

        Set<PathCandidate> collisions = new HashSet<>();
        for (List<PathCandidate> group : filesByPath.values()) {
            if (group.size() > 1) {
                collisions.addAll(group);
            }
        }
        for (PathCandidate candidate : candidates) {
            Path parent = candidate.path().getParent();
            while (parent != null) {
                List<PathCandidate> filesAtParent = filesByPath.get(collisionKey(parent));
                if (filesAtParent != null) {
                    collisions.addAll(filesAtParent);
                }
                parent = parent.getParent();
            }
        }
        return collisions;
    }

    private static void validateFinalPath(Path output,
            Il2CppClassCatalog.ClassEntry entry,
            Map<String, Il2CppClassCatalog.ClassEntry> finalFiles,
            Set<String> finalDirectories) throws IOException {
        String outputKey = collisionKey(output);
        var previous = finalFiles.putIfAbsent(outputKey, entry);
        if (previous != null) {
            throw new IOException("class output path collision: " + previous.displayName() +
                    " and " + entry.displayName());
        }
        if (finalDirectories.contains(outputKey)) {
            throw new IOException("class output path conflicts with an output directory: " +
                    entry.displayName());
        }

        Path parent = output.getParent();
        while (parent != null) {
            String parentKey = collisionKey(parent);
            if (finalFiles.containsKey(parentKey)) {
                throw new IOException("class output directory conflicts with an output file: " +
                        entry.displayName());
            }
            finalDirectories.add(parentKey);
            parent = parent.getParent();
        }
    }

    private static String stableSuffix(Il2CppClassCatalog.ClassEntry entry) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            update(digest, entry.assembly());
            update(digest, entry.relativeSource());
            return HexFormat.of().withUpperCase()
                    .formatHex(digest.digest(), 0, SUFFIX_BYTES);
        }
        catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 is unavailable", error);
        }
    }

    private static void update(MessageDigest digest, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        digest.update((byte) (bytes.length >>> 24));
        digest.update((byte) (bytes.length >>> 16));
        digest.update((byte) (bytes.length >>> 8));
        digest.update((byte) bytes.length);
        digest.update(bytes);
    }

    private static String collisionKey(Path path) {
        return path.toString().replace('\\', '/').toLowerCase(Locale.ROOT);
    }

    private record PathCandidate(Il2CppClassCatalog.ClassEntry entry, Path path) {
    }

    private record ClassIdentity(String assembly, String relativeSource) {
    }
}
