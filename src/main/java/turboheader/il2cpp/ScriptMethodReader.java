package turboheader.il2cpp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

/** Reads the useful IL2CPP tables without materializing the rest of script.json. */
public final class ScriptMethodReader {
    private ScriptMethodReader() {
    }

    public static List<ScriptMethod> read(Path path) throws IOException {
        return readAll(path).methods();
    }

    public static ScriptData readAll(Path path) throws IOException {
        List<ScriptMethod> methods = new ArrayList<>();
        List<ScriptMetadata> metadata = new ArrayList<>();
        List<ScriptMetadataMethod> metadataMethods = new ArrayList<>();
        List<ScriptString> strings = new ArrayList<>();
        try (JsonReader reader = new JsonReader(Files.newBufferedReader(path, StandardCharsets.UTF_8))) {
            reader.beginObject();
            boolean foundMethods = false;
            boolean foundMetadata = false;
            boolean foundMetadataMethods = false;
            boolean foundStrings = false;
            while (reader.hasNext()) {
                String property = reader.nextName();
                switch (property) {
                    case "ScriptMethod" -> {
                        if (foundMethods || reader.peek() != JsonToken.BEGIN_ARRAY) {
                            throw new IOException("script.json ScriptMethod must be one array");
                        }
                        foundMethods = true;
                        reader.beginArray();
                        while (reader.hasNext()) {
                            methods.add(readMethod(reader));
                        }
                        reader.endArray();
                    }
                    case "ScriptMetadata" -> {
                        if (foundMetadata || reader.peek() != JsonToken.BEGIN_ARRAY) {
                            throw new IOException("script.json ScriptMetadata must be one array");
                        }
                        foundMetadata = true;
                        reader.beginArray();
                        while (reader.hasNext()) {
                            metadata.add(readMetadata(reader));
                        }
                        reader.endArray();
                    }
                    case "ScriptMetadataMethod" -> {
                        if (foundMetadataMethods || reader.peek() != JsonToken.BEGIN_ARRAY) {
                            throw new IOException(
                                    "script.json ScriptMetadataMethod must be one array");
                        }
                        foundMetadataMethods = true;
                        reader.beginArray();
                        while (reader.hasNext()) {
                            metadataMethods.add(readMetadataMethod(reader));
                        }
                        reader.endArray();
                    }
                    case "ScriptString" -> {
                        if (foundStrings || reader.peek() != JsonToken.BEGIN_ARRAY) {
                            throw new IOException("script.json ScriptString must be one array");
                        }
                        foundStrings = true;
                        reader.beginArray();
                        while (reader.hasNext()) {
                            strings.add(readString(reader));
                        }
                        reader.endArray();
                    }
                    default -> reader.skipValue();
                }
            }
            reader.endObject();
            if (!foundMethods) {
                throw new IOException("script.json has no ScriptMethod array");
            }
        }
        return new ScriptData(List.copyOf(methods), List.copyOf(metadata),
                List.copyOf(metadataMethods), List.copyOf(strings));
    }

    private static ScriptMethod readMethod(JsonReader reader) throws IOException {
        Long address = null;
        String name = null;
        String signature = null;
        String typeSignature = null;
        String assembly = null;
        reader.beginObject();
        while (reader.hasNext()) {
            switch (reader.nextName()) {
                case "Address" -> address = reader.nextLong();
                case "Name" -> name = reader.nextString();
                case "Signature" -> signature = reader.nextString();
                case "TypeSignature" -> typeSignature = reader.nextString();
                case "Assembly" -> assembly = reader.nextString();
                default -> reader.skipValue();
            }
        }
        reader.endObject();
        if (address == null || address < 0 || name == null || signature == null || typeSignature == null) {
            throw new IOException("invalid ScriptMethod entry at index data offset " +
                    reader.getPath());
        }
        return new ScriptMethod(address, name, signature, typeSignature, assembly);
    }

    private static ScriptMetadata readMetadata(JsonReader reader) throws IOException {
        Long address = null;
        String name = null;
        String signature = null;
        reader.beginObject();
        while (reader.hasNext()) {
            switch (reader.nextName()) {
                case "Address" -> address = reader.nextLong();
                case "Name" -> name = reader.nextString();
                case "Signature" -> {
                    if (reader.peek() == JsonToken.NULL) {
                        reader.nextNull();
                    }
                    else {
                        signature = reader.nextString();
                    }
                }
                default -> reader.skipValue();
            }
        }
        reader.endObject();
        if (address == null || address < 0 || name == null) {
            throw new IOException("invalid ScriptMetadata entry at index data offset " +
                    reader.getPath());
        }
        return new ScriptMetadata(address, name, signature);
    }

    private static ScriptString readString(JsonReader reader) throws IOException {
        Long address = null;
        String value = null;
        reader.beginObject();
        while (reader.hasNext()) {
            switch (reader.nextName()) {
                case "Address" -> address = reader.nextLong();
                case "Value" -> value = reader.nextString();
                default -> reader.skipValue();
            }
        }
        reader.endObject();
        if (address == null || address < 0 || value == null) {
            throw new IOException("invalid ScriptString entry at index data offset " +
                    reader.getPath());
        }
        return new ScriptString(address, value);
    }

    private static ScriptMetadataMethod readMetadataMethod(JsonReader reader) throws IOException {
        Long address = null;
        String name = null;
        Long methodAddress = null;
        reader.beginObject();
        while (reader.hasNext()) {
            switch (reader.nextName()) {
                case "Address" -> address = reader.nextLong();
                case "Name" -> name = reader.nextString();
                case "MethodAddress" -> methodAddress = reader.nextLong();
                default -> reader.skipValue();
            }
        }
        reader.endObject();
        if (address == null || address < 0 || name == null || methodAddress == null ||
                methodAddress < 0) {
            throw new IOException("invalid ScriptMetadataMethod entry at index data offset " +
                    reader.getPath());
        }
        return new ScriptMetadataMethod(address, name, methodAddress);
    }

    public record ScriptMethod(long address, String name, String signature, String typeSignature,
            String assembly) {
    }

    public record ScriptMetadata(long address, String name, String signature) {
    }

    public record ScriptString(long address, String value) {
    }

    public record ScriptMetadataMethod(long address, String name, long methodAddress) {
    }

    public record ScriptData(List<ScriptMethod> methods, List<ScriptMetadata> metadata,
            List<ScriptMetadataMethod> metadataMethods, List<ScriptString> strings) {
    }
}
