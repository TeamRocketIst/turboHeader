package turboheader.il2cpp;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** JNI entry point for the high-throughput C parser. */
public final class NativeParser {
    private static final int EXPECTED_NATIVE_API_VERSION = 4;
    private static final long MAX_OFFSET_INPUT_BYTES = 128L * 1024L * 1024L;
    private static volatile boolean apiChecked;

    private NativeParser() {
    }

    public static TypeModel.Model parse(Path header, Path offsets, int pointerSize) throws IOException {
        if (header == null || !Files.isRegularFile(header)) {
            throw new IOException("IL2CPP header does not exist: " + header);
        }
        if (offsets != null && !Files.isRegularFile(offsets)) {
            throw new IOException("offset file does not exist: " + offsets);
        }
        if (offsets != null && Files.size(offsets) > MAX_OFFSET_INPUT_BYTES) {
            throw new IOException("offset input exceeds " + MAX_OFFSET_INPUT_BYTES +
                    " byte limit: " + offsets);
        }
        if (pointerSize != 4 && pointerSize != 8) {
            throw new IOException("pointer size must be 4 or 8");
        }
        nativeApiVersion();
        byte[] blob = parse0(header.toAbsolutePath().toString(),
                offsets == null ? null : offsets.toAbsolutePath().toString(), pointerSize);
        return ModelDecoder.decode(blob);
    }

    public static synchronized int nativeApiVersion() throws IOException {
        NativeLibraryLoader.load();
        if (apiChecked) {
            return EXPECTED_NATIVE_API_VERSION;
        }
        final int actual;
        try {
            actual = apiVersion0();
        }
        catch (UnsatisfiedLinkError error) {
            throw new IOException("TurboHeader native library is incompatible with this extension; " +
                    "reinstall the complete extension", error);
        }
        if (actual != EXPECTED_NATIVE_API_VERSION) {
            throw new IOException("TurboHeader native API mismatch: expected " +
                    EXPECTED_NATIVE_API_VERSION + ", got " + actual + ". Reinstall the complete extension.");
        }
        apiChecked = true;
        return actual;
    }

    private static native int apiVersion0();
    private static native byte[] parse0(String header, String offsets, int pointerSize) throws IOException;
}
