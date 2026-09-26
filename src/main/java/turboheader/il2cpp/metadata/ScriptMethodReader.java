package turboheader.il2cpp.metadata;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

/** Reads the useful IL2CPP tables without materializing the rest of script.json. */
public final class ScriptMethodReader {
    private static final int MAX_INTERFACE_DISPATCH_ENTRIES = 1_000_000;
    private static final int MAX_SIGNATURE_CHARS = 65_536;

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
        List<ScriptInterfaceDispatch> interfaceDispatch = new ArrayList<>();
        boolean foundInterfaceDispatch = false;
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
                    case "ScriptInterfaceDispatch" -> {
                        if (foundInterfaceDispatch || reader.peek() != JsonToken.BEGIN_ARRAY) {
                            throw new IOException(
                                    "script.json ScriptInterfaceDispatch must be one array");
                        }
                        foundInterfaceDispatch = true;
                        reader.beginArray();
                        while (reader.hasNext()) {
                            if (interfaceDispatch.size() == MAX_INTERFACE_DISPATCH_ENTRIES) {
                                throw new IOException(
                                        "script.json has too many interface-dispatch entries");
                            }
                            interfaceDispatch.add(readInterfaceDispatch(reader));
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
        Optional<List<ScriptInterfaceDispatch>> dispatch = foundInterfaceDispatch
                ? Optional.of(List.copyOf(interfaceDispatch))
                : Optional.empty();
        return new ScriptData(List.copyOf(methods), List.copyOf(metadata),
                List.copyOf(metadataMethods), List.copyOf(strings), dispatch);
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
        Integer typeId = null;
        boolean foundTypeId = false;
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
                case "TypeId" -> {
                    if (foundTypeId) {
                        throw new IOException("duplicate ScriptMetadata TypeId");
                    }
                    foundTypeId = true;
                    typeId = readNonNegativeInt(reader, "ScriptMetadata TypeId");
                }
                default -> reader.skipValue();
            }
        }
        reader.endObject();
        if (address == null || address < 0 || name == null) {
            throw new IOException("invalid ScriptMetadata entry at index data offset " +
                    reader.getPath());
        }
        return new ScriptMetadata(address, name, signature, typeId);
    }

    private static ScriptInterfaceDispatch readInterfaceDispatch(JsonReader reader)
            throws IOException {
        Integer receiverTypeId = null;
        Integer interfaceTypeId = null;
        Integer interfaceSlot = null;
        Long methodAddress = null;
        String signature = null;
        Set<String> fields = new HashSet<>();
        reader.beginObject();
        while (reader.hasNext()) {
            String field = reader.nextName();
            if (!fields.add(field)) {
                throw new IOException("duplicate interface-dispatch field: " + field);
            }
            switch (field) {
                case "ReceiverTypeId" -> receiverTypeId = readNonNegativeInt(reader, field);
                case "InterfaceTypeId" -> interfaceTypeId = readNonNegativeInt(reader, field);
                case "InterfaceSlot" -> interfaceSlot = readNonNegativeInt(reader, field);
                case "MethodAddress" -> methodAddress = readPositiveLong(reader, field);
                case "Signature" -> {
                    if (reader.peek() != JsonToken.STRING) {
                        throw new IOException("Signature must be a string");
                    }
                    signature = reader.nextString();
                    if (signature.isBlank() || signature.length() > MAX_SIGNATURE_CHARS ||
                            signature.indexOf('\r') >= 0 || signature.indexOf('\n') >= 0 ||
                            signature.indexOf('\t') >= 0) {
                        throw new IOException("invalid interface-dispatch signature");
                    }
                }
                default -> reader.skipValue();
            }
        }
        reader.endObject();
        if (receiverTypeId == null || interfaceTypeId == null || interfaceSlot == null ||
                methodAddress == null || signature == null) {
            throw new IOException("incomplete interface-dispatch entry at " + reader.getPath());
        }
        return new ScriptInterfaceDispatch(receiverTypeId, interfaceTypeId, interfaceSlot,
                methodAddress, signature);
    }

    private static int readNonNegativeInt(JsonReader reader, String field) throws IOException {
        if (reader.peek() != JsonToken.NUMBER) {
            throw new IOException(field + " must be an integer");
        }
        try {
            int value = reader.nextInt();
            if (value < 0) {
                throw new IOException(field + " must not be negative");
            }
            return value;
        }
        catch (NumberFormatException e) {
            throw new IOException(field + " must be an integer", e);
        }
    }

    private static long readPositiveLong(JsonReader reader, String field) throws IOException {
        if (reader.peek() != JsonToken.NUMBER) {
            throw new IOException(field + " must be an integer");
        }
        try {
            long value = reader.nextLong();
            if (value <= 0) {
                throw new IOException(field + " must be positive");
            }
            return value;
        }
        catch (NumberFormatException e) {
            throw new IOException(field + " must be an integer", e);
        }
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

    public record ScriptMetadata(long address, String name, String signature, Integer typeId) {
        public ScriptMetadata(long address, String name, String signature) {
            this(address, name, signature, null);
        }
    }

    public record ScriptString(long address, String value) {
    }

    public record ScriptMetadataMethod(long address, String name, long methodAddress) {
    }

    public record ScriptInterfaceDispatch(int receiverTypeId, int interfaceTypeId,
            int interfaceSlot, long methodAddress, String signature) {
    }

    public record ScriptData(List<ScriptMethod> methods, List<ScriptMetadata> metadata,
            List<ScriptMetadataMethod> metadataMethods, List<ScriptString> strings,
            Optional<List<ScriptInterfaceDispatch>> interfaceDispatch) {
        public ScriptData(List<ScriptMethod> methods, List<ScriptMetadata> metadata,
                List<ScriptMetadataMethod> metadataMethods, List<ScriptString> strings) {
            this(methods, metadata, metadataMethods, strings, Optional.empty());
        }
    }
}
