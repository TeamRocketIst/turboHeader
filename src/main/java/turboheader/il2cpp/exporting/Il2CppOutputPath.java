package turboheader.il2cpp.exporting;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class Il2CppOutputPath {
    private static final String OUTPUT_EXTENSION = ".cpp";
    private static final String COLLISION_MARKER = "~C";

    private Il2CppOutputPath() {
    }

    public static Path forClass(Il2CppClassCatalog.ClassEntry entry) {
        return build(Objects.requireNonNull(entry, "entry"), null);
    }

    public static Map<Il2CppClassCatalog.ClassEntry, Path> forClasses(
            List<Il2CppClassCatalog.ClassEntry> classes) throws IOException {
        return Il2CppOutputPathAllocator.allocate(classes);
    }

    static Path withCollisionSuffix(Il2CppClassCatalog.ClassEntry entry, String suffix) {
        return build(Objects.requireNonNull(entry, "entry"),
                Objects.requireNonNull(suffix, "suffix"));
    }

    private static Path build(Il2CppClassCatalog.ClassEntry entry, String suffix) {
        List<String> parts = new ArrayList<>();
        parts.add(PortableFilenameEncoder.encode(entry.assembly()));

        String[] sourceParts = entry.relativeSource().split("/", -1);
        for (int index = 0; index < sourceParts.length; index++) {
            String part = sourceParts[index];
            if (part.isEmpty() || part.equals(".") || part.equals("..")) {
                throw new IllegalArgumentException("invalid class output path");
            }
            if (index + 1 < sourceParts.length) {
                parts.add(PortableFilenameEncoder.encode(part));
                continue;
            }

            String className = part.substring(0, part.length() - 3);
            int suffixLength = suffix == null ? 0 : COLLISION_MARKER.length() + suffix.length();
            int classNameLimit = PortableFilenameEncoder.MAX_COMPONENT_LENGTH -
                    OUTPUT_EXTENSION.length() - suffixLength;
            String encoded = PortableFilenameEncoder.encode(className, classNameLimit);
            String collisionSuffix = suffix == null ? "" : COLLISION_MARKER + suffix;
            parts.add(encoded + collisionSuffix + OUTPUT_EXTENSION);
        }

        Path result = Path.of(parts.get(0));
        for (int index = 1; index < parts.size(); index++) {
            result = result.resolve(parts.get(index));
        }
        return result;
    }
}
