package turboheader.il2cpp.metadata;

import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

final class Il2CppDelegateSignatureCodec {
    private static final int MAGIC = 0x54484453;
    private static final int VERSION = 1;
    private static final int HEADER_BYTES = 12;
    private static final int ENTRY_HEADER_BYTES = 12;
    private static final int MAX_ENTRIES = 1_000_000;
    private static final int MAX_OBJECT_TYPE_BYTES = 16_384;
    private static final int MAX_SIGNATURE_BYTES = 262_144;
    private static final int MAX_CATALOGUE_BYTES = 64 * 1024 * 1024;

    private Il2CppDelegateSignatureCodec() {
    }

    static byte[] encode(Il2CppDelegateSignatureCatalog catalog) {
        int count = catalog.entries().size();
        checkCount(count);
        List<byte[]> objectTypes = new ArrayList<>(count);
        List<byte[]> signatures = new ArrayList<>(count);
        long length = HEADER_BYTES;
        for (var entry : catalog.entries()) {
            byte[] objectType = entry.objectType().getBytes(StandardCharsets.UTF_8);
            byte[] signature = entry.signature().getBytes(StandardCharsets.UTF_8);
            checkTextLength(objectType.length, MAX_OBJECT_TYPE_BYTES);
            checkTextLength(signature.length, MAX_SIGNATURE_BYTES);
            length += ENTRY_HEADER_BYTES + (long) objectType.length + signature.length;
            if (length > MAX_CATALOGUE_BYTES) {
                throw new IllegalArgumentException("delegate-signature catalogue is too large");
            }
            objectTypes.add(objectType);
            signatures.add(signature);
        }

        ByteBuffer out = ByteBuffer.allocate((int) length).order(ByteOrder.BIG_ENDIAN);
        out.putInt(MAGIC);
        out.putInt(VERSION);
        out.putInt(count);
        for (int i = 0; i < count; i++) {
            var entry = catalog.entries().get(i);
            byte[] objectType = objectTypes.get(i);
            byte[] signature = signatures.get(i);
            out.putInt(entry.typeId());
            out.putInt(objectType.length);
            out.putInt(signature.length);
            out.put(objectType);
            out.put(signature);
        }
        return out.array();
    }

    static Il2CppDelegateSignatureCatalog decode(byte[] encoded) throws IOException {
        if (encoded == null || encoded.length < HEADER_BYTES ||
                encoded.length > MAX_CATALOGUE_BYTES) {
            throw new IOException("invalid stored delegate-signature catalogue");
        }

        try {
            ByteBuffer in = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
            if (in.getInt() != MAGIC || in.getInt() != VERSION) {
                throw new IOException("unsupported stored delegate-signature catalogue");
            }
            int count = readCount(in);
            List<Il2CppDelegateSignatureCatalog.Entry> entries = new ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                int typeId = in.getInt();
                int objectLength = readLength(in, MAX_OBJECT_TYPE_BYTES, "object type");
                int signatureLength = readLength(in, MAX_SIGNATURE_BYTES, "signature");
                if (typeId < 0 || objectLength + (long) signatureLength > in.remaining()) {
                    throw new IOException("invalid stored delegate-signature entry");
                }
                String objectType = readUtf8(in, objectLength);
                String signature = readUtf8(in, signatureLength);
                entries.add(new Il2CppDelegateSignatureCatalog.Entry(
                        typeId, objectType, signature));
            }
            if (in.hasRemaining()) {
                throw new IOException("trailing stored delegate-signature data");
            }
            return Il2CppDelegateSignatureCatalog.restored(entries);
        }
        catch (BufferUnderflowException e) {
            throw new IOException("truncated stored delegate-signature catalogue", e);
        }
    }

    private static String readUtf8(ByteBuffer in, int length) throws IOException {
        ByteBuffer value = in.slice();
        value.limit(length);
        try {
            String result = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(value).toString();
            in.position(in.position() + length);
            return result;
        }
        catch (CharacterCodingException e) {
            throw new IOException("invalid UTF-8 in delegate-signature catalogue", e);
        }
    }

    private static int readCount(ByteBuffer in) throws IOException {
        int count = in.getInt();
        if (count < 0 || count > MAX_ENTRIES) {
            throw new IOException("invalid stored delegate-signature count");
        }
        return count;
    }

    private static int readLength(ByteBuffer in, int maximum, String description)
            throws IOException {
        int length = in.getInt();
        if (length <= 0 || length > maximum) {
            throw new IOException("invalid stored delegate " + description + " length");
        }
        return length;
    }

    private static void checkCount(int count) {
        if (count < 0 || count > MAX_ENTRIES) {
            throw new IllegalArgumentException("delegate-signature catalogue is too large");
        }
    }

    private static void checkTextLength(int length, int maximum) {
        if (length <= 0 || length > maximum) {
            throw new IllegalArgumentException("delegate-signature text is too large");
        }
    }
}
