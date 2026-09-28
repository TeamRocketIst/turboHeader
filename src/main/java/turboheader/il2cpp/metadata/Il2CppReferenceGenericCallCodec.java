package turboheader.il2cpp.metadata;

import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

final class Il2CppReferenceGenericCallCodec {
    private static final int MAGIC = 0x54485247;
    private static final int VERSION = 1;
    private static final int MAX_SIGNATURE_BYTES = 262_144;

    private Il2CppReferenceGenericCallCodec() {
    }

    static byte[] encode(Il2CppReferenceGenericCallCatalog catalog) throws IOException {
        var signatures = new ArrayList<byte[]>(catalog.entries().size());
        long length = Il2CppReferenceGenericCallCatalog.HEADER_BYTES;
        for (var entry : catalog.entries()) {
            byte[] signature = Il2CppReferenceGenericCallCatalog.signatureBytes(entry.signature());
            length += Il2CppReferenceGenericCallCatalog.ENTRY_HEADER_BYTES + (long) signature.length;
            if (length > Il2CppReferenceGenericCallCatalog.MAX_CATALOGUE_BYTES) {
                throw new IOException("reference-generic catalogue is too large");
            }
            signatures.add(signature);
        }
        ByteBuffer out = ByteBuffer.allocate((int) length).order(ByteOrder.BIG_ENDIAN);
        out.putInt(MAGIC).putInt(VERSION).putInt(catalog.entries().size());
        for (int index = 0; index < signatures.size(); index++) {
            var entry = catalog.entries().get(index);
            byte[] signature = signatures.get(index);
            out.putLong(entry.methodInfoAddress()).putInt(entry.methodSpecIndex());
            out.putLong(entry.methodAddress()).putInt(signature.length).put(signature);
        }
        return out.array();
    }

    static Il2CppReferenceGenericCallCatalog decode(byte[] encoded) throws IOException {
        if (encoded == null || encoded.length < Il2CppReferenceGenericCallCatalog.HEADER_BYTES ||
                encoded.length > Il2CppReferenceGenericCallCatalog.MAX_CATALOGUE_BYTES) {
            throw new IOException("invalid stored reference-generic catalogue size");
        }
        try {
            ByteBuffer in = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
            if (in.getInt() != MAGIC || in.getInt() != VERSION) {
                throw new IOException("unsupported stored reference-generic catalogue");
            }
            int count = in.getInt();
            if (count < 0 || count > Il2CppReferenceGenericCallCatalog.MAX_ENTRIES ||
                    count > in.remaining() / (Il2CppReferenceGenericCallCatalog.ENTRY_HEADER_BYTES + 1)) {
                throw new IOException("invalid stored reference-generic count");
            }
            var entries = new ArrayList<Il2CppReferenceGenericCallCatalog.Entry>(count);
            for (int index = 0; index < count; index++) {
                long slot = in.getLong();
                int spec = in.getInt();
                long target = in.getLong();
                int length = in.getInt();
                if (length <= 0 || length > MAX_SIGNATURE_BYTES || length > in.remaining()) {
                    throw new IOException("invalid stored reference-generic signature length");
                }
                ByteBuffer text = in.slice();
                text.limit(length);
                String signature = StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(text).toString();
                in.position(in.position() + length);
                entries.add(new Il2CppReferenceGenericCallCatalog.Entry(slot, spec, target, signature));
            }
            if (in.hasRemaining()) {
                throw new IOException("trailing stored reference-generic data");
            }
            return Il2CppReferenceGenericCallCatalog.restored(entries);
        }
        catch (BufferUnderflowException | CharacterCodingException e) {
            throw new IOException("invalid stored reference-generic data", e);
        }
    }
}
