package turboheader.il2cpp;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;

public final class JniSmokeTest {
    public static void main(String[] args) throws Exception {
        if (NativeParser.nativeApiVersion() != 4) {
            throw new AssertionError("unexpected native API version");
        }
        TypeModel.Model model = NativeParser.parse(Path.of(args[0]), Path.of(args[1]), 8);
        long fields = model.structures().stream().mapToLong(s -> s.fields().size()).sum();
        if (model.structures().size() != 6 || fields != 18 || model.missingOffsets() != 0) {
            throw new AssertionError("unexpected JNI model: structures=" + model.structures().size() +
                    " fields=" + fields + " missing=" + model.missingOffsets());
        }
        Path oversized = Files.createTempFile("turboheader-oversized-offsets", ".json");
        try {
            try (RandomAccessFile file = new RandomAccessFile(oversized.toFile(), "rw")) {
                file.setLength(128L * 1024L * 1024L + 1L);
            }
            try {
                NativeParser.parse(Path.of(args[0]), oversized, 8);
                throw new AssertionError("oversized offset file was accepted");
            }
            catch (IOException expected) {
                if (!expected.getMessage().contains("exceeds 134217728 byte limit")) {
                    throw expected;
                }
            }
        }
        finally {
            Files.deleteIfExists(oversized);
        }
        System.out.println("JNI parser test passed: structures=" + model.structures().size() +
                " fields=" + fields);
    }
}
