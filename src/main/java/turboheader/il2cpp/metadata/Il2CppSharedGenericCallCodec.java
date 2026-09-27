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

final class Il2CppSharedGenericCallCodec {
    private static final int MAGIC = 0x54485347;
    private static final int VERSION = 1;
    private static final int HEADER_BYTES = 12;
    private static final int ENTRY_HEADER_BYTES = 20;
    private static final int MAX_ENTRIES = 1_000_000;
    private static final int MAX_SIGNATURE_BYTES = 262_144;
    private static final int MAX_CATALOGUE_BYTES = 64 * 1024 * 1024;

    private Il2CppSharedGenericCallCodec() {
    }

    static byte[] encode(Il2CppSharedGenericCallCatalog catalog) {
        int count = catalog.entries().size();
        checkCount(count);
        List<byte[]> signatures = new ArrayList<>(count);
        long length = HEADER_BYTES;
        for (var entry : catalog.entries()) {
            byte[] signature = entry.signature().getBytes(StandardCharsets.UTF_8);
            if (signature.length == 0 || signature.length > MAX_SIGNATURE_BYTES) {
                throw new IllegalArgumentException("shared-generic signature is too large");
            }
            length += ENTRY_HEADER_BYTES + (long) signature.length;
            if (length > MAX_CATALOGUE_BYTES) {
                throw new IllegalArgumentException("shared-generic catalogue is too large");
            }
            signatures.add(signature);
        }

        ByteBuffer out = ByteBuffer.allocate((int) length).order(ByteOrder.BIG_ENDIAN);
        out.putInt(MAGIC);
        out.putInt(VERSION);
        out.putInt(count);
        for (int index = 0; index < count; index++) {
            var entry = catalog.entries().get(index);
            byte[] signature = signatures.get(index);
            out.putLong(entry.methodInfoAddress());
            out.putLong(entry.methodAddress());
            out.putInt(signature.length);
            out.put(signature);
        }
        return out.array();
    }

    static Il2CppSharedGenericCallCatalog decode(byte[] encoded) throws IOException {
        if (encoded == null || encoded.length < HEADER_BYTES ||
                encoded.length > MAX_CATALOGUE_BYTES) {
            throw new IOException("invalid stored shared-generic catalogue");
        }
        try {
            ByteBuffer in = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
            if (in.getInt() != MAGIC || in.getInt() != VERSION) {
                throw new IOException("unsupported stored shared-generic catalogue");
            }
            int count = readCount(in);
            List<Il2CppSharedGenericCallCatalog.Entry> entries = new ArrayList<>(count);
            for (int index = 0; index < count; index++) {
                long methodInfoAddress = in.getLong();
                long methodAddress = in.getLong();
                int signatureLength = readLength(in);
                if (methodInfoAddress <= 0 || methodAddress <= 0 ||
                        signatureLength > in.remaining()) {
                    throw new IOException("invalid stored shared-generic entry");
                }
                entries.add(new Il2CppSharedGenericCallCatalog.Entry(
                        methodInfoAddress, methodAddress, readUtf8(in, signatureLength)));
            }
            if (in.hasRemaining()) {
                throw new IOException("trailing stored shared-generic data");
            }
            return Il2CppSharedGenericCallCatalog.restored(entries);
        }
        catch (BufferUnderflowException e) {
            throw new IOException("truncated stored shared-generic catalogue", e);
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
            throw new IOException("invalid UTF-8 in shared-generic catalogue", e);
        }
    }

    private static int readCount(ByteBuffer in) throws IOException {
        int count = in.getInt();
        if (count < 0 || count > MAX_ENTRIES) {
            throw new IOException("invalid stored shared-generic count");
        }
        return count;
    }

    private static int readLength(ByteBuffer in) throws IOException {
        int length = in.getInt();
        if (length <= 0 || length > MAX_SIGNATURE_BYTES) {
            throw new IOException("invalid stored shared-generic signature length");
        }
        return length;
    }

    private static void checkCount(int count) {
        if (count < 0 || count > MAX_ENTRIES) {
            throw new IllegalArgumentException("shared-generic catalogue is too large");
        }
    }
}
