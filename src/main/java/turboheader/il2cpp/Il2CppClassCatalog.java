package turboheader.il2cpp;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

public final class Il2CppClassCatalog {
    private Il2CppClassCatalog() {
    }

    public static List<ClassEntry> scan(Path directory) throws IOException {
        Path root = regularDirectory(directory, "class source");
        List<ClassEntry> classes = new ArrayList<>();

        for (Path assembly : children(root)) {
            rejectSymlink(assembly);
            if (!Files.isDirectory(assembly, LinkOption.NOFOLLOW_LINKS)) {
                continue;
            }
            String assemblyName = assembly.getFileName().toString();
            try (var paths = Files.walk(assembly)) {
                List<Path> files = paths.sorted(Comparator.comparing(
                        path -> portable(assembly.relativize(path)))).toList();
                for (Path file : files) {
                    rejectSymlink(file);
                    if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) ||
                            !isCSharp(file)) {
                        continue;
                    }
                    String relative = portable(assembly.relativize(file));
                    classes.add(new ClassEntry(assemblyName, relative,
                            file.toRealPath(LinkOption.NOFOLLOW_LINKS)));
                }
            }
        }
        return List.copyOf(classes);
    }

    private static List<Path> children(Path directory) throws IOException {
        try (var paths = Files.list(directory)) {
            return paths.sorted(Comparator.comparing(
                    path -> path.getFileName().toString())).toList();
        }
    }

    private static Path regularDirectory(Path path, String description) throws IOException {
        if (Files.isSymbolicLink(path) ||
                !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException(description + " must identify a directory");
        }
        return path.toRealPath(LinkOption.NOFOLLOW_LINKS);
    }

    private static void rejectSymlink(Path path) throws IOException {
        if (Files.isSymbolicLink(path)) {
            throw new IOException("class source must not contain symbolic links: " + path);
        }
    }

    private static boolean isCSharp(Path path) {
        return path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".cs");
    }

    private static String portable(Path path) {
        return path.toString().replace('\\', '/');
    }

    public record ClassEntry(String assembly, String relativeSource, Path source,
            String namespaceName, String className) {
        public ClassEntry(String assembly, String relativeSource, Path source) {
            this(assembly, relativeSource, source, namespaceOf(relativeSource),
                    classNameOf(relativeSource));
        }

        public ClassEntry {
            Objects.requireNonNull(assembly, "assembly");
            Objects.requireNonNull(relativeSource, "relativeSource");
            Objects.requireNonNull(source, "source");
            Objects.requireNonNull(namespaceName, "namespaceName");
            Objects.requireNonNull(className, "className");
            if (assembly.isEmpty() || relativeSource.isEmpty() || className.isEmpty()) {
                throw new IllegalArgumentException("class identity must not be empty");
            }
            if (relativeSource.indexOf('\\') >= 0 || relativeSource.startsWith("/") ||
                    relativeSource.equals("..") ||
                    relativeSource.startsWith("../") || relativeSource.contains("/../")) {
                throw new IllegalArgumentException("class source path must be relative");
            }
        }

        public String displayName() {
            return assembly + "/" + relativeSource.substring(0, relativeSource.length() - 3);
        }

        public Set<String> selectionKeys() {
            String withoutExtension = relativeSource.substring(0, relativeSource.length() - 3);
            Set<String> keys = new LinkedHashSet<>();
            keys.add(normalize(className));
            keys.add(normalize(withoutExtension));
            keys.add(normalize(withoutExtension.replace('/', '.')));
            keys.add(normalize(relativeSource));
            if (!namespaceName.isEmpty()) {
                keys.add(normalize(namespaceName + "." + className));
            }
            return Collections.unmodifiableSet(keys);
        }

        public Set<String> candidateNames() {
            String withoutExtension = relativeSource.substring(0, relativeSource.length() - 3);
            Set<String> names = new LinkedHashSet<>();
            names.add(className);
            names.add(withoutExtension);
            names.add(withoutExtension.replace('/', '.'));
            names.add(withoutExtension.replace('/', '_'));
            if (!namespaceName.isEmpty()) {
                names.add(namespaceName + "." + className);
                names.add(namespaceName.replace('.', '_') + "_" + className);
            }
            return Collections.unmodifiableSet(names);
        }

        private static String namespaceOf(String relativeSource) {
            int separator = relativeSource.lastIndexOf('/');
            return separator < 0 ? "" : relativeSource.substring(0, separator).replace('/', '.');
        }

        private static String classNameOf(String relativeSource) {
            int separator = relativeSource.lastIndexOf('/');
            String fileName = relativeSource.substring(separator + 1);
            if (fileName.toLowerCase(Locale.ROOT).endsWith(".cs")) {
                return fileName.substring(0, fileName.length() - 3);
            }
            throw new IllegalArgumentException("class source must end in .cs");
        }

        private static String normalize(String value) {
            return value.toLowerCase(Locale.ROOT);
        }
    }
}
