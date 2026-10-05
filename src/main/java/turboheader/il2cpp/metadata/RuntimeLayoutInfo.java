package turboheader.il2cpp.metadata;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

/** Runtime-header confidence, separate from managed field-offset provenance. */
public record RuntimeLayoutInfo(String status, int pointerSize, boolean runtimeFieldsVerified, String profile) {
    private static final Set<String> STATUSES = Set.of(
            "verified", "familyFallback", "legacyCompatibility", "opaque");
    private static final Set<String> PROFILES = Set.of(
            "legacy", "stack-handle32", "stack-handle-pointer", "class-init-union", "interface-data");

    public RuntimeLayoutInfo {
        if (status == null || !STATUSES.contains(status) || (pointerSize != 4 && pointerSize != 8) ||
                runtimeFieldsVerified != status.equals("verified") ||
                profile == null || profile.length() > 64 ||
                (runtimeFieldsVerified && (pointerSize != 8 || !PROFILES.contains(profile)))) {
            throw new IllegalArgumentException("invalid runtime layout confidence");
        }
    }

    static RuntimeLayoutInfo read(JsonReader reader) throws IOException {
        if (reader.peek() != JsonToken.BEGIN_OBJECT) throw new IOException("RuntimeLayout must be an object");
        String status = null;
        String profile = null;
        Integer pointerSize = null;
        Boolean verified = null;
        Set<String> fields = new HashSet<>();
        reader.beginObject();
        while (reader.hasNext()) {
            String field = reader.nextName();
            if (fields.size() == 16 || !fields.add(field)) {
                throw new IOException("duplicate or excessive RuntimeLayout fields");
            }
            switch (field) {
                case "status", "profile" -> {
                    if (reader.peek() != JsonToken.STRING) throw new IOException("invalid RuntimeLayout text");
                    String value = reader.nextString();
                    if (value.length() > 64) throw new IOException("RuntimeLayout text is too long");
                    if (field.equals("status")) status = value;
                    else profile = value;
                }
                case "pointerSize" -> {
                    if (reader.peek() != JsonToken.NUMBER) throw new IOException("invalid RuntimeLayout pointer size");
                    String value = reader.nextString();
                    if (!value.equals("4") && !value.equals("8")) throw new IOException("invalid RuntimeLayout pointer size");
                    pointerSize = Integer.parseInt(value);
                }
                case "runtimeFieldsVerified" -> {
                    if (reader.peek() != JsonToken.BOOLEAN) throw new IOException("invalid RuntimeLayout verification flag");
                    verified = reader.nextBoolean();
                }
                default -> reader.skipValue();
            }
        }
        reader.endObject();
        if (status == null || pointerSize == null || verified == null || profile == null ||
                (verified && !PROFILES.contains(profile))) {
            throw new IOException("incomplete or unknown RuntimeLayout");
        }
        try {
            return new RuntimeLayoutInfo(status, pointerSize, verified, profile);
        }
        catch (IllegalArgumentException e) {
            throw new IOException("invalid RuntimeLayout confidence", e);
        }
    }

    public static Optional<RuntimeLayoutInfo> readOffsets(Path path) throws IOException {
        if (Files.size(path) > 64L * 1024 * 1024) throw new IOException("offset file exceeds the runtime reader limit");
        Optional<RuntimeLayoutInfo> layout = Optional.empty();
        try (JsonReader reader = new JsonReader(Files.newBufferedReader(path, StandardCharsets.UTF_8))) {
            reader.beginObject();
            while (reader.hasNext()) {
                if (reader.nextName().equals("runtimeLayout")) {
                    if (layout.isPresent()) throw new IOException("duplicate runtimeLayout");
                    layout = Optional.of(read(reader));
                }
                else reader.skipValue();
            }
            reader.endObject();
            if (reader.peek() != JsonToken.END_DOCUMENT) throw new IOException("offset file contains trailing data");
        }
        return layout;
    }
}
