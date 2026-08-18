package turboheader.il2cpp;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Parses an optional, already-proven i2c noreturn address set. */
final class NoreturnSeedReader {
    private NoreturnSeedReader() {
    }

    static SeedInput load(String seedPath) throws IOException {
        if (seedPath == null || seedPath.isBlank()) {
            return SeedInput.unavailable();
        }
        Path path = Path.of(seedPath).toAbsolutePath().normalize();
        if (!Files.isRegularFile(path)) {
            throw new IOException("Noreturn seed file does not exist: " + path);
        }
        Set<Long> addresses = new HashSet<>();
        int lineNumber = 0;
        for (String line : Files.readAllLines(path)) {
            lineNumber++;
            String value = line.strip();
            if (value.isEmpty() || value.startsWith("#")) {
                continue;
            }
            if (value.startsWith("0x") || value.startsWith("0X")) {
                value = value.substring(2);
            }
            try {
                addresses.add(Long.parseUnsignedLong(value, 16));
            }
            catch (NumberFormatException e) {
                throw new IOException("Invalid noreturn seed at " + path + ":" +
                        lineNumber + ": " + line, e);
            }
        }
        if (addresses.isEmpty()) {
            throw new IOException("Noreturn seed file contains no addresses: " + path);
        }
        return new SeedInput(true, Set.copyOf(addresses));
    }

    static List<Long> ordered(Set<Long> addresses) {
        List<Long> result = new ArrayList<>(addresses);
        result.sort(Long::compareUnsigned);
        return List.copyOf(result);
    }

    record SeedInput(boolean usable, Set<Long> addresses) {
        static SeedInput unavailable() {
            return new SeedInput(false, Set.of());
        }
    }
}
