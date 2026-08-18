package turboheader.il2cpp;

import static turboheader.il2cpp.TypeModel.FieldDef;
import static turboheader.il2cpp.TypeModel.MissingOffsetReasons;
import static turboheader.il2cpp.TypeModel.Model;
import static turboheader.il2cpp.TypeModel.LayoutEvidence;
import static turboheader.il2cpp.TypeModel.OffsetSource;
import static turboheader.il2cpp.TypeModel.StructDef;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Decodes the compact I2GF stream produced by the native parser. */
public final class ModelDecoder {
    private static final int MAGIC = 0x46473249; // "I2GF" in little-endian
    private static final int VERSION_1 = 1;
    private static final int VERSION_2 = 2;
    private static final int VERSION_3 = 3;
    private static final int MAX_COUNT = 20_000_000;
    private static final int MAX_STRING_BYTES = 16 * 1024 * 1024;

    private ModelDecoder() {
    }

    public static Model decode(byte[] bytes) throws IOException {
        try {
            return decodeModel(bytes);
        }
        catch (IllegalArgumentException error) {
            throw new IOException("invalid I2GF model: " + error.getMessage(), error);
        }
    }

    private static Model decodeModel(byte[] bytes) throws IOException {
        if (bytes == null || bytes.length < 20) {
            throw new IOException("truncated I2GF model");
        }
        ByteBuffer in = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        int magic = getInt(in, "magic");
        int version = getInt(in, "version");
        if (magic != MAGIC) {
            throw new IOException("not an I2GF model (bad magic)");
        }
        if (version != VERSION_1 && version != VERSION_2 && version != VERSION_3) {
            throw new IOException("unsupported I2GF version: " + version);
        }

        int pointerSize = getInt(in, "pointer size");
        if (pointerSize != 4 && pointerSize != 8) {
            throw new IOException("invalid pointer size: " + pointerSize);
        }
        int structCount = checkedCount(getInt(in, "structure count"), "structure count");
        int missingOffsets = getInt(in, "missing offset count");
        if (missingOffsets < 0) {
            throw new IOException("invalid missing offset count");
        }
        MissingOffsetReasons missingOffsetReasons;
        if (version >= VERSION_2) {
            int openGeneric = checkedCount(getInt(in, "open-generic missing count"),
                    "open-generic missing count");
            int concreteAbsent = checkedCount(getInt(in, "concrete-sidecar missing count"),
                    "concrete-sidecar missing count");
            int genericParent = checkedCount(getInt(in, "generic-parent missing count"),
                    "generic-parent missing count");
            int objectHeader = checkedCount(getInt(in, "object-header missing count"),
                    "object-header missing count");
            int unsupported = checkedCount(getInt(in, "unsupported-layout missing count"),
                    "unsupported-layout missing count");
            long reasonTotal = (long) openGeneric + concreteAbsent + genericParent + objectHeader +
                    unsupported;
            if (reasonTotal != missingOffsets) {
                throw new IOException("missing-offset reason total " + reasonTotal +
                        " does not match missing offset count " + missingOffsets);
            }
            missingOffsetReasons = new MissingOffsetReasons(openGeneric, concreteAbsent, genericParent,
                    objectHeader, unsupported, 0);
        }
        else {
            missingOffsetReasons = MissingOffsetReasons.legacy(missingOffsets);
        }

        OffsetSource offsetSource = OffsetSource.LEGACY_UNKNOWN;
        int offsetSchemaVersion = 0;
        if (version == VERSION_3) {
            offsetSource = OffsetSource.fromWire(getInt(in, "offset source"));
            offsetSchemaVersion = checkedCount(getInt(in, "offset schema version"),
                    "offset schema version");
        }

        List<StructDef> structures = new ArrayList<>(Math.min(structCount, 1_000_000));
        for (int i = 0; i < structCount; i++) {
            String name = getString(in, "structure name");
            int length = getInt(in, "structure length");
            LayoutEvidence lengthEvidence = version == VERSION_3
                    ? LayoutEvidence.fromWire(getInt(in, "structure length evidence"))
                    : LayoutEvidence.LEGACY_UNKNOWN;
            int fieldCount = checkedCount(getInt(in, "field count"), "field count");
            if (length < 1) {
                throw new IOException("invalid length for " + name + ": " + length);
            }
            List<FieldDef> fields = new ArrayList<>(Math.min(fieldCount, 100_000));
            for (int j = 0; j < fieldCount; j++) {
                int offset = getInt(in, "field offset");
                if (offset < 0) {
                    throw new IOException("negative field offset in " + name);
                }
                LayoutEvidence offsetEvidence = version == VERSION_3
                        ? LayoutEvidence.fromWire(getInt(in, "field offset evidence"))
                        : LayoutEvidence.LEGACY_UNKNOWN;
                String fieldName = getString(in, "field name");
                String cType = getString(in, "field type");
                fields.add(new FieldDef(offset, fieldName, cType, offsetEvidence));
            }
            structures.add(new StructDef(name, length, fields, lengthEvidence));
        }
        if (in.hasRemaining()) {
            throw new IOException("I2GF model has " + in.remaining() + " trailing bytes");
        }
        return new Model(pointerSize, missingOffsets, structures, missingOffsetReasons,
                offsetSource, offsetSchemaVersion);
    }

    private static int checkedCount(int value, String what) throws IOException {
        if (value < 0 || value > MAX_COUNT) {
            throw new IOException("invalid " + what + ": " + Integer.toUnsignedString(value));
        }
        return value;
    }

    private static int getInt(ByteBuffer in, String what) throws IOException {
        if (in.remaining() < Integer.BYTES) {
            throw new IOException("truncated I2GF " + what);
        }
        return in.getInt();
    }

    private static String getString(ByteBuffer in, String what) throws IOException {
        int length = getInt(in, what + " length");
        if (length < 0 || length > MAX_STRING_BYTES || length > in.remaining()) {
            throw new IOException("invalid " + what + " length: " + Integer.toUnsignedString(length));
        }
        byte[] value = new byte[length];
        in.get(value);
        String decoded = new String(value, StandardCharsets.UTF_8);
        if (decoded.indexOf('\0') >= 0) {
            throw new IOException(what + " contains NUL");
        }
        return decoded;
    }
}
