package turboheader.il2cpp;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HashSet;
import java.util.Set;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.MalformedJsonException;

public final class HeadlessRequestReader {
    private static final int MAX_MANIFEST_BYTES = 1024 * 1024;
    private static final int MAX_PATH_CHARS = 32768;

    private HeadlessRequestReader() {
    }

    public static ImportRequest readImport(Path path) throws IOException {
        String json = decodeUtf8(readManifest(path));
        try (JsonReader reader = new JsonReader(new StringReader(json))) {
            Integer schema = null;
            String operation = null;
            String header = null;
            String offsets = null;
            String methods = null;
            String policy = null;
            Set<String> fields = new HashSet<>();

            requireToken(reader, JsonToken.BEGIN_OBJECT, "request must be a JSON object");
            reader.beginObject();
            while (reader.hasNext()) {
                String field = reader.nextName();
                if (!fields.add(field)) {
                    throw new IOException("duplicate request field: " + field);
                }
                switch (field) {
                    case "schema" -> schema = readInteger(reader, field);
                    case "operation" -> operation = readString(reader, field);
                    case "header" -> header = readString(reader, field);
                    case "offsets" -> offsets = readNullableString(reader, field);
                    case "methods" -> methods = readNullableString(reader, field);
                    case "layoutPolicy" -> policy = readString(reader, field);
                    default -> throw new IOException("unknown request field: " + field);
                }
            }
            reader.endObject();
            requireEnd(reader);

            requireField(fields, "schema");
            requireField(fields, "operation");
            requireField(fields, "header");
            requireField(fields, "offsets");
            requireField(fields, "methods");
            requireField(fields, "layoutPolicy");
            if (schema == null || schema != 1) {
                throw new IOException("unsupported request schema: " + schema);
            }
            if (!"import".equals(operation)) {
                throw new IOException("request operation must be import");
            }

            Path headerPath = regularFile(header, "header");
            Path offsetsPath = offsets == null ? null : regularFile(offsets, "offsets");
            Path methodsPath = methods == null ? null : regularFile(methods, "methods");
            return new ImportRequest(headerPath, offsetsPath, methodsPath,
                    LayoutPolicy.parse(policy));
        }
        catch (IllegalStateException error) {
            throw new IOException("invalid request JSON", error);
        }
    }

    public static ExportRequest readExport(Path path) throws IOException {
        String json = decodeUtf8(readManifest(path));
        try (JsonReader reader = new JsonReader(new StringReader(json))) {
            Integer schema = null;
            String operation = null;
            String classSource = null;
            String output = null;
            String scope = null;
            String frameworkRules = null;
            String noreturnSeeds = null;
            Integer decompileJobs = null;
            Set<String> fields = new HashSet<>();

            requireToken(reader, JsonToken.BEGIN_OBJECT, "request must be a JSON object");
            reader.beginObject();
            while (reader.hasNext()) {
                String field = reader.nextName();
                if (!fields.add(field)) {
                    throw new IOException("duplicate request field: " + field);
                }
                switch (field) {
                    case "schema" -> schema = readInteger(reader, field);
                    case "operation" -> operation = readString(reader, field);
                    case "classSource" -> classSource = readString(reader, field);
                    case "output" -> output = readString(reader, field);
                    case "scope" -> scope = readString(reader, field);
                    case "frameworkRules" -> frameworkRules = readNullableString(reader, field);
                    case "noreturnSeeds" -> noreturnSeeds = readNullableString(reader, field);
                    case "decompileJobs" -> decompileJobs = readInteger(reader, field);
                    default -> throw new IOException("unknown request field: " + field);
                }
            }
            reader.endObject();
            requireEnd(reader);

            requireField(fields, "schema");
            requireField(fields, "operation");
            requireField(fields, "classSource");
            requireField(fields, "output");
            requireField(fields, "scope");
            requireField(fields, "frameworkRules");
            requireField(fields, "noreturnSeeds");
            requireField(fields, "decompileJobs");
            if (schema == null || schema != 1) {
                throw new IOException("unsupported request schema: " + schema);
            }
            if (!"export".equals(operation)) {
                throw new IOException("request operation must be export");
            }
            if (decompileJobs == null || decompileJobs < 0 || decompileJobs > 12) {
                throw new IOException("decompileJobs must be between 0 and 12");
            }

            Path classSourcePath = regularDirectory(classSource, "classSource");
            Path outputPath = outputDirectory(output);
            Path rulesPath = frameworkRules == null ? null : regularFile(
                    frameworkRules, "frameworkRules");
            Path seedsPath = noreturnSeeds == null ? null : regularFile(
                    noreturnSeeds, "noreturnSeeds");
            return new ExportRequest(classSourcePath, outputPath, ExportScope.parse(scope),
                    rulesPath, seedsPath, decompileJobs);
        }
        catch (IllegalStateException error) {
            throw new IOException("invalid request JSON", error);
        }
    }

    private static byte[] readManifest(Path path) throws IOException {
        if (!path.isAbsolute()) {
            throw new IOException("request manifest path must be absolute");
        }
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("request manifest must be a regular file");
        }
        Set<OpenOption> options = Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
        try (SeekableByteChannel channel = Files.newByteChannel(path, options);
                InputStream stream = Channels.newInputStream(channel)) {
            if (channel.size() > MAX_MANIFEST_BYTES) {
                throw new IOException("request manifest exceeds 1 MiB");
            }
            byte[] contents = stream.readNBytes(MAX_MANIFEST_BYTES + 1);
            if (contents.length > MAX_MANIFEST_BYTES) {
                throw new IOException("request manifest exceeds 1 MiB");
            }
            return contents;
        }
    }

    private static String decodeUtf8(byte[] contents) throws IOException {
        var decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            return decoder.decode(ByteBuffer.wrap(contents)).toString();
        }
        catch (CharacterCodingException error) {
            throw new IOException("request manifest is not valid UTF-8", error);
        }
    }

    private static void requireToken(JsonReader reader, JsonToken token, String message)
            throws IOException {
        if (reader.peek() != token) {
            throw new IOException(message);
        }
    }

    private static int readInteger(JsonReader reader, String field) throws IOException {
        requireToken(reader, JsonToken.NUMBER, field + " must be an integer");
        try {
            return reader.nextInt();
        }
        catch (NumberFormatException error) {
            throw new IOException(field + " must be an integer", error);
        }
    }

    private static String readString(JsonReader reader, String field) throws IOException {
        requireToken(reader, JsonToken.STRING, field + " must be a string");
        return reader.nextString();
    }

    private static String readNullableString(JsonReader reader, String field) throws IOException {
        if (reader.peek() == JsonToken.NULL) {
            reader.nextNull();
            return null;
        }
        return readString(reader, field);
    }

    private static void requireField(Set<String> fields, String field) throws IOException {
        if (!fields.contains(field)) {
            throw new IOException("missing request field: " + field);
        }
    }

    private static void requireEnd(JsonReader reader) throws IOException {
        try {
            requireToken(reader, JsonToken.END_DOCUMENT, "request has trailing JSON data");
        }
        catch (MalformedJsonException error) {
            throw new IOException("request has trailing JSON data", error);
        }
    }

    private static Path regularFile(String value, String field) throws IOException {
        Path path = absolutePath(value, field);
        if (Files.isSymbolicLink(path) ||
                !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException(field + " path must identify a regular file");
        }
        return path.toRealPath(LinkOption.NOFOLLOW_LINKS);
    }

    private static Path regularDirectory(String value, String field) throws IOException {
        Path path = absolutePath(value, field);
        if (Files.isSymbolicLink(path) ||
                !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException(field + " path must identify a directory");
        }
        return path.toRealPath(LinkOption.NOFOLLOW_LINKS);
    }

    private static Path outputDirectory(String value) throws IOException {
        Path path = absolutePath(value, "output");
        if (Files.isSymbolicLink(path)) {
            throw new IOException("output path must not be a symbolic link");
        }
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("output path must identify a directory");
            }
            return path.toRealPath(LinkOption.NOFOLLOW_LINKS);
        }

        Path parent = path.getParent();
        if (parent == null || !Files.isDirectory(parent)) {
            throw new IOException("output parent must identify a directory");
        }
        return parent.toRealPath().resolve(path.getFileName());
    }

    private static Path absolutePath(String value, String field) throws IOException {
        if (value == null || value.isEmpty() || value.length() > MAX_PATH_CHARS) {
            throw new IOException("invalid " + field + " path");
        }
        try {
            Path path = Path.of(value);
            if (!path.isAbsolute()) {
                throw new IOException(field + " path must be absolute");
            }
            return path;
        }
        catch (InvalidPathException error) {
            throw new IOException("invalid " + field + " path", error);
        }
    }

    public enum LayoutPolicy {
        ALLOW_INFERRED,
        REQUIRE_EXTERNAL_OFFSETS,
        REQUIRE_AUTHORITATIVE;

        static LayoutPolicy parse(String value) throws IOException {
            return switch (value) {
                case "allow-inferred" -> ALLOW_INFERRED;
                case "require-external-offsets" -> REQUIRE_EXTERNAL_OFFSETS;
                case "require-authoritative" -> REQUIRE_AUTHORITATIVE;
                default -> throw new IOException("unknown layout policy: " + value);
            };
        }
    }

    public enum ExportScope {
        WHITELIST,
        BLACKLIST,
        ALL;

        static ExportScope parse(String value) throws IOException {
            return switch (value) {
                case "whitelist" -> WHITELIST;
                case "blacklist" -> BLACKLIST;
                case "all" -> ALL;
                default -> throw new IOException("unknown export scope: " + value);
            };
        }
    }

    public record ImportRequest(Path header, Path offsets, Path methods,
            LayoutPolicy layoutPolicy) {
    }

    public record ExportRequest(Path classSource, Path output, ExportScope scope,
            Path frameworkRules, Path noreturnSeeds, int decompileJobs) {
    }
}
