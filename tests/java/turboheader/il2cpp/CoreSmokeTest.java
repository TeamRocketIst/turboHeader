package turboheader.il2cpp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class CoreSmokeTest {
    public static void main(String[] args) throws Exception {
        byte[] good = Files.readAllBytes(Path.of(args[0]));
        TypeModel.Model model = ModelDecoder.decode(good);
        check(model.pointerSize() == 8, "pointer size");
        check(model.structures().size() == 6, "structure count");
        check(model.structures().stream().anyMatch(s -> s.name().equals("Derived_o") && s.length() == 60),
                "Derived_o");
        check(model.missingOffsetReasons().total() == model.missingOffsets(), "reason total");
        check(model.offsetSource() == TypeModel.OffsetSource.TYPE_OFFSETS_JSON, "offset source");
        check(model.evidenceCounts().total() == 18, "evidence count");
        check(model.lengthEvidenceCounts().total() == model.structures().size(),
                "length evidence count");
        check(TypeModel.OffsetSource.TYPE_OFFSETS_JSON.wireValue() == 2,
                "offset source wire value");
        check(TypeModel.LayoutEvidence.ABI_DEFINED.wireValue() == 3,
                "layout evidence wire value");

        TypeModel.Model legacy = ModelDecoder.decode(encodeLegacy(model, 1));
        check(legacy.structures().size() == model.structures().size(), "v1 structure count");
        check(legacy.missingOffsetReasons().legacyUnclassified() == legacy.missingOffsets(),
                "v1 missing offsets remain compatible");
        check(legacy.offsetSource() == TypeModel.OffsetSource.LEGACY_UNKNOWN,
                "v1 provenance remains unknown");

        TypeModel.Model versionTwo = ModelDecoder.decode(encodeLegacy(model, 2));
        check(versionTwo.missingOffsetReasons().equals(model.missingOffsetReasons()),
                "v2 reason counts");
        check(versionTwo.offsetSource() == TypeModel.OffsetSource.LEGACY_UNKNOWN,
                "v2 provenance remains unknown");

        byte[] badReasonTotal = good.clone();
        badReasonTotal[20] ^= 1;
        expectFailure(badReasonTotal, "reason total");

        byte[] badSource = good.clone();
        badSource[40] = 0x7f;
        expectFailure(badSource, "offset source");

        int firstNameLength = readInt(good, 48);
        int lengthEvidenceOffset = 48 + 4 + firstNameLength + 4;
        byte[] badLengthEvidence = good.clone();
        badLengthEvidence[lengthEvidenceOffset] = 0x7f;
        expectFailure(badLengthEvidence, "structure length evidence");

        int fieldEvidenceOffset = lengthEvidenceOffset + 4 + 4 + 4;
        byte[] badFieldEvidence = good.clone();
        badFieldEvidence[fieldEvidenceOffset] = 0x7f;
        expectFailure(badFieldEvidence, "field offset evidence");

        byte[] inconsistentSchema = good.clone();
        writeInt(inconsistentSchema, 40, 0);
        expectFailure(inconsistentSchema, "legacy source with JSON schema");

        byte[] inconsistentHeaderEvidence = good.clone();
        writeInt(inconsistentHeaderEvidence, 40, 1);
        writeInt(inconsistentHeaderEvidence, 44, 0);
        writeInt(inconsistentHeaderEvidence, fieldEvidenceOffset, 1);
        expectFailure(inconsistentHeaderEvidence, "header source with sidecar evidence");

        expectFailure(Arrays.copyOf(good, 10), "truncation");
        byte[] badMagic = good.clone();
        badMagic[0] ^= 0x7f;
        expectFailure(badMagic, "magic");
        byte[] trailing = Arrays.copyOf(good, good.length + 1);
        expectFailure(trailing, "trailing data");
        System.out.println("Java model decoder tests passed");
    }

    private static byte[] encodeLegacy(TypeModel.Model model, int version) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        writeInt(output, 0x46473249);
        writeInt(output, version);
        writeInt(output, model.pointerSize());
        writeInt(output, model.structures().size());
        writeInt(output, model.missingOffsets());
        if (version == 2) {
            var reasons = model.missingOffsetReasons();
            writeInt(output, reasons.openGenericDefinition());
            writeInt(output, reasons.concreteInstanceAbsent());
            writeInt(output, reasons.unresolvedGenericParent());
            writeInt(output, reasons.objectHeaderOffset());
            writeInt(output, reasons.unsupportedLayout());
        }
        for (var structure : model.structures()) {
            writeString(output, structure.name());
            writeInt(output, structure.length());
            writeInt(output, structure.fields().size());
            for (var field : structure.fields()) {
                writeInt(output, field.offset());
                writeString(output, field.name());
                writeString(output, field.cType());
            }
        }
        return output.toByteArray();
    }

    private static void writeString(ByteArrayOutputStream output, String text) {
        byte[] value = text.getBytes(StandardCharsets.UTF_8);
        writeInt(output, value.length);
        output.writeBytes(value);
    }

    private static void writeInt(ByteArrayOutputStream output, int value) {
        output.write(value);
        output.write(value >>> 8);
        output.write(value >>> 16);
        output.write(value >>> 24);
    }

    private static int readInt(byte[] bytes, int offset) {
        return (bytes[offset] & 0xff) | (bytes[offset + 1] & 0xff) << 8 |
                (bytes[offset + 2] & 0xff) << 16 | (bytes[offset + 3] & 0xff) << 24;
    }

    private static void writeInt(byte[] bytes, int offset, int value) {
        bytes[offset] = (byte) value;
        bytes[offset + 1] = (byte) (value >>> 8);
        bytes[offset + 2] = (byte) (value >>> 16);
        bytes[offset + 3] = (byte) (value >>> 24);
    }

    private static void expectFailure(byte[] bytes, String label) throws Exception {
        try {
            ModelDecoder.decode(bytes);
            throw new AssertionError("expected failure: " + label);
        }
        catch (IOException expected) {
            // expected
        }
    }

    private static void check(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }
}
