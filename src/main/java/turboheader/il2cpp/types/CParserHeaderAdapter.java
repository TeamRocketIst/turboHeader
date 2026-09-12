package turboheader.il2cpp.types;

import java.io.BufferedReader;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Writer;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Creates the restricted C header accepted by Ghidra's CParser. */
public final class CParserHeaderAdapter {
    static final long MAX_HEADER_BYTES = 128L * 1024L * 1024L;
    private static final Pattern INHERITANCE = Pattern.compile(
            "^(\\s*)struct\\s+(\\S+)\\s*:\\s*(\\S+)\\s*\\{\\s*$");

    private CParserHeaderAdapter() {
    }

    public static PreparedHeader prepare(Path source, int pointerSize, Path temporaryDirectory)
            throws IOException {
        return prepare(source, pointerSize, temporaryDirectory, MAX_HEADER_BYTES);
    }

    static PreparedHeader prepare(Path source, int pointerSize, Path temporaryDirectory,
            long maximumBytes) throws IOException {
        if (pointerSize != 4 && pointerSize != 8) {
            throw new IllegalArgumentException(
                    "Program pointer size must be 4 or 8, got " + pointerSize);
        }
        if (maximumBytes <= 0) {
            throw new IllegalArgumentException("Header size limit must be positive");
        }
        Path root = temporaryDirectory.toAbsolutePath().normalize();
        if (Files.isSymbolicLink(root) || !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("CParser temporary directory must be a regular directory");
        }

        Path converted = Files.createTempFile(root, "turboheader-cparser-", ".h");
        boolean complete = false;
        try {
            int conversions = convert(source, converted, pointerSize, maximumBytes);
            complete = true;
            return new PreparedHeader(converted, conversions);
        }
        finally {
            if (!complete) {
                Files.deleteIfExists(converted);
            }
        }
    }

    private static int convert(Path source, Path destination, int pointerSize,
            long maximumBytes) throws IOException {
        var decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        int conversions = 0;
        Set<OpenOption> options = Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
        try (SeekableByteChannel channel = Files.newByteChannel(source, options)) {
            if (channel.size() > maximumBytes) {
                throw sizeLimitError(maximumBytes);
            }
            InputStream bounded = new BoundedInputStream(
                    Channels.newInputStream(channel), maximumBytes);
            try (BufferedReader input = new BufferedReader(
                    new InputStreamReader(bounded, decoder));
                    Writer output = Files.newBufferedWriter(destination, StandardCharsets.UTF_8,
                            StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                output.write(preamble(pointerSize));
                String line;
                while ((line = input.readLine()) != null) {
                    validateLine(line);
                    Matcher inheritance = INHERITANCE.matcher(line);
                    if (inheritance.matches()) {
                        output.write(inheritance.group(1));
                        output.write("struct ");
                        output.write(inheritance.group(2));
                        output.write(" {\n");
                        output.write(inheritance.group(1));
                        output.write(" ");
                        output.write(inheritance.group(3));
                        output.write(" super;\n");
                        conversions++;
                    }
                    else {
                        output.write(line);
                        output.write("\n");
                    }
                }
            }
        }
        return conversions;
    }

    private static void validateLine(String line) throws IOException {
        if (line.indexOf('#') >= 0 || line.contains("%:") || line.contains("??=")) {
            throw new IOException("IL2CPP header contains a preprocessor token");
        }
        for (int i = 0; i < line.length(); i++) {
            char value = line.charAt(i);
            if (value != '\t' && Character.isISOControl(value)) {
                throw new IOException("IL2CPP header contains a control character");
            }
        }
    }

    private static IOException sizeLimitError(long maximumBytes) {
        return new IOException("IL2CPP header exceeds " + maximumBytes + " byte limit");
    }

    private static String preamble(int pointerSize) {
        String pointer = pointerSize == 8 ? "__int64" : "__int32";
        String unsignedPointer = "unsigned " + pointer;
        return "typedef unsigned __int8 uint8_t;\n" +
                "typedef unsigned __int16 uint16_t;\n" +
                "typedef unsigned __int32 uint32_t;\n" +
                "typedef unsigned __int64 uint64_t;\n" +
                "typedef __int8 int8_t;\n" +
                "typedef __int16 int16_t;\n" +
                "typedef __int32 int32_t;\n" +
                "typedef __int64 int64_t;\n" +
                "typedef " + pointer + " intptr_t;\n" +
                "typedef " + unsignedPointer + " uintptr_t;\n" +
                "typedef " + unsignedPointer + " size_t;\n";
    }

    public static final class PreparedHeader implements AutoCloseable {
        private final Path path;
        private final int inheritanceConversions;

        private PreparedHeader(Path path, int inheritanceConversions) {
            this.path = path;
            this.inheritanceConversions = inheritanceConversions;
        }

        public Path path() {
            return path;
        }

        public int inheritanceConversions() {
            return inheritanceConversions;
        }

        @Override
        public void close() throws IOException {
            Files.deleteIfExists(path);
        }
    }

    private static final class BoundedInputStream extends FilterInputStream {
        private final long maximumBytes;
        private long bytesRead;

        private BoundedInputStream(InputStream input, long maximumBytes) {
            super(input);
            this.maximumBytes = maximumBytes;
        }

        @Override
        public int read() throws IOException {
            int value = super.read();
            if (value >= 0) {
                count(1);
            }
            return value;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            int count = super.read(buffer, offset, length);
            if (count > 0) {
                count(count);
            }
            return count;
        }

        private void count(int amount) throws IOException {
            bytesRead += amount;
            if (bytesRead > maximumBytes) {
                throw sizeLimitError(maximumBytes);
            }
        }
    }
}
