package turboheader.il2cpp.metadata;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.LinkedHashMap;
import java.util.Map;

final class Il2CppInterfaceDispatchCodec {
    private static final int MAGIC = 0x54484944;
    private static final int VERSION = 1;
    private static final int HEADER_BYTES = 16;
    private static final int TYPE_BYTES = 12;
    private static final int DISPATCH_BYTES = 20;
    private static final int MAX_ENTRIES = 1_000_000;

    private Il2CppInterfaceDispatchCodec() {
    }

    static byte[] encode(Il2CppInterfaceDispatchCatalog catalog) {
        int typeCount = catalog.typeIdsByMetadataAddress().size();
        int dispatchCount = catalog.methodAddresses().size();
        checkCount(typeCount);
        checkCount(dispatchCount);
        long length = HEADER_BYTES + (long) typeCount * TYPE_BYTES +
                (long) dispatchCount * DISPATCH_BYTES;
        if (length > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("interface-dispatch catalogue is too large");
        }

        ByteBuffer out = ByteBuffer.allocate((int) length).order(ByteOrder.BIG_ENDIAN);
        out.putInt(MAGIC);
        out.putInt(VERSION);
        out.putInt(typeCount);
        out.putInt(dispatchCount);
        for (var entry : catalog.typeIdsByMetadataAddress().entrySet()) {
            out.putLong(entry.getKey());
            out.putInt(entry.getValue());
        }
        for (var entry : catalog.methodAddresses().entrySet()) {
            var key = entry.getKey();
            out.putInt(key.receiverTypeId());
            out.putInt(key.interfaceTypeId());
            out.putInt(key.interfaceSlot());
            out.putLong(entry.getValue());
        }
        return out.array();
    }

    static Il2CppInterfaceDispatchCatalog decode(byte[] encoded) throws IOException {
        if (encoded == null || encoded.length < HEADER_BYTES) {
            throw new IOException("invalid stored interface-dispatch catalogue");
        }
        ByteBuffer in = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
        if (in.getInt() != MAGIC || in.getInt() != VERSION) {
            throw new IOException("unsupported stored interface-dispatch catalogue");
        }
        int typeCount = readCount(in, "type identity");
        int dispatchCount = readCount(in, "dispatch");
        long expected = HEADER_BYTES + (long) typeCount * TYPE_BYTES +
                (long) dispatchCount * DISPATCH_BYTES;
        if (expected != encoded.length) {
            throw new IOException("invalid stored interface-dispatch catalogue length");
        }

        Map<Long, Integer> typeIds = new LinkedHashMap<>();
        for (int i = 0; i < typeCount; i++) {
            long address = in.getLong();
            int typeId = in.getInt();
            if (address < 0 || typeId < 0 || typeIds.putIfAbsent(address, typeId) != null) {
                throw new IOException("invalid stored interface-dispatch type identity");
            }
        }

        Map<Il2CppInterfaceDispatchCatalog.DispatchKey, Long> dispatch =
                new LinkedHashMap<>();
        for (int i = 0; i < dispatchCount; i++) {
            int receiver = in.getInt();
            int interfaceType = in.getInt();
            int slot = in.getInt();
            long methodAddress = in.getLong();
            Il2CppInterfaceDispatchCatalog.DispatchKey key;
            try {
                key = new Il2CppInterfaceDispatchCatalog.DispatchKey(
                        receiver, interfaceType, slot);
            }
            catch (IllegalArgumentException e) {
                throw new IOException("invalid stored interface-dispatch key", e);
            }
            if (methodAddress <= 0 || dispatch.putIfAbsent(key, methodAddress) != null) {
                throw new IOException("invalid stored interface-dispatch entry");
            }
        }
        return Il2CppInterfaceDispatchCatalog.restored(typeIds, dispatch);
    }

    private static int readCount(ByteBuffer in, String description) throws IOException {
        int count = in.getInt();
        if (count < 0 || count > MAX_ENTRIES) {
            throw new IOException("invalid stored " + description + " count");
        }
        return count;
    }

    private static void checkCount(int count) {
        if (count < 0 || count > MAX_ENTRIES) {
            throw new IllegalArgumentException("interface-dispatch catalogue is too large");
        }
    }
}
