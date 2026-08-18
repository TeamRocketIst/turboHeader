package turboheader.il2cpp;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

public final class NoreturnSeedReaderTest {
    public static void main(String[] args) throws Exception {
        absentPathSelectsLocalDiscovery();
        validFileIsParsedAndOrderedUnsigned();
        explicitEmptyFileIsRejected();
        malformedFileIsRejected();
        System.out.println("noreturn seed-reader tests passed");
    }

    private static void absentPathSelectsLocalDiscovery() throws Exception {
        require(!NoreturnSeedReader.load("").usable(), "blank path should be unavailable");
        require(!NoreturnSeedReader.load(null).usable(), "null path should be unavailable");
    }

    private static void validFileIsParsedAndOrderedUnsigned() throws Exception {
        Path path = Files.createTempFile("noreturn-seeds", ".txt");
        try {
            Files.writeString(path, "# generated\n0x20\n10\nfffffffffffffff0\n20\n");
            var input = NoreturnSeedReader.load(path.toString());
            require(input.usable(), "explicit valid path should be usable");
            require(input.addresses().equals(Set.of(0x10L, 0x20L, 0xffff_ffff_ffff_fff0L)),
                    "parsed seed set");
            require(NoreturnSeedReader.ordered(input.addresses()).equals(
                    List.of(0x10L, 0x20L, 0xffff_ffff_ffff_fff0L)),
                    "unsigned deterministic order");
        }
        finally {
            Files.deleteIfExists(path);
        }
    }

    private static void explicitEmptyFileIsRejected() throws Exception {
        Path path = Files.createTempFile("noreturn-seeds-empty", ".txt");
        try {
            Files.writeString(path, "# no addresses\n\n");
            expectIOException(() -> NoreturnSeedReader.load(path.toString()), "no addresses");
        }
        finally {
            Files.deleteIfExists(path);
        }
    }

    private static void malformedFileIsRejected() throws Exception {
        Path path = Files.createTempFile("noreturn-seeds-invalid", ".txt");
        try {
            Files.writeString(path, "not-hex\n");
            expectIOException(() -> NoreturnSeedReader.load(path.toString()), "Invalid noreturn seed");
        }
        finally {
            Files.deleteIfExists(path);
        }
    }

    private static void expectIOException(ThrowingRunnable action, String message) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected IOException containing: " + message);
        }
        catch (IOException error) {
            require(error.getMessage().contains(message), "unexpected IOException: " + error.getMessage());
        }
    }

    private static void require(boolean value, String message) {
        if (!value) {
            throw new AssertionError(message);
        }
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
