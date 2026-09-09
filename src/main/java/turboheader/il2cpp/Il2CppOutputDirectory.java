package turboheader.il2cpp;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;

import ghidra.util.exception.CancelledException;

final class Il2CppOutputDirectory {
    private final Path root;

    private Il2CppOutputDirectory(Path root) {
        this.root = root;
    }

    static Il2CppOutputDirectory open(Path requested) throws IOException {
        Path root = requested.toAbsolutePath().normalize();
        if (Files.isSymbolicLink(root)) {
            throw new IOException("output path must not be a symbolic link");
        }
        if (Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
            if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("output path must identify a directory");
            }
            return new Il2CppOutputDirectory(root.toRealPath(LinkOption.NOFOLLOW_LINKS));
        }

        Path parent = root.getParent();
        if (parent == null || Files.isSymbolicLink(parent) ||
                !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("output parent must identify a regular directory");
        }
        try {
            Files.createDirectory(root);
        }
        catch (FileAlreadyExistsException error) {
            if (Files.isSymbolicLink(root) ||
                    !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("output path changed while creating it", error);
            }
        }
        return new Il2CppOutputDirectory(root.toRealPath(LinkOption.NOFOLLOW_LINKS));
    }

    long write(Path relative, WriteAction action) throws IOException, CancelledException {
        Path output = resolve(relative);
        Path temporary = Files.createTempFile(output.getParent(), ".turboheader-", ".tmp");
        boolean moved = false;
        try {
            try (BufferedWriter writer = Files.newBufferedWriter(temporary,
                    StandardCharsets.UTF_8, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING, LinkOption.NOFOLLOW_LINKS)) {
                action.write(writer);
            }
            long size = Files.size(temporary);
            move(temporary, output);
            moved = true;
            return size;
        }
        finally {
            if (!moved) {
                Files.deleteIfExists(temporary);
            }
        }
    }

    void deleteIfRegular(Path relative) throws IOException {
        Path path = resolve(relative);
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        if (Files.isSymbolicLink(path) ||
                !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("diagnostic output must identify a regular file");
        }
        Files.delete(path);
    }

    private Path resolve(Path relative) throws IOException {
        if (relative.isAbsolute() || !relative.normalize().equals(relative)) {
            throw new IOException("output file path must be normalized and relative");
        }
        Path fileName = relative.getFileName();
        if (fileName == null || fileName.toString().isEmpty()) {
            throw new IOException("output file path has no filename");
        }

        Path directory = root;
        Path parent = relative.getParent();
        if (parent != null) {
            for (Path component : parent) {
                String name = component.toString();
                if (name.isEmpty() || name.equals(".") || name.equals("..")) {
                    throw new IOException("output directory contains an invalid component");
                }
                directory = ensureDirectory(directory.resolve(component));
            }
        }

        Path output = directory.resolve(fileName);
        if (!output.normalize().startsWith(root)) {
            throw new IOException("output file escapes the output directory");
        }
        if (Files.isSymbolicLink(output) ||
                Files.isDirectory(output, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("output file must not be a symbolic link or directory");
        }
        return output;
    }

    private static Path ensureDirectory(Path directory) throws IOException {
        if (Files.isSymbolicLink(directory)) {
            throw new IOException("output directory must not contain symbolic links");
        }
        if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
            try {
                Files.createDirectory(directory);
            }
            catch (FileAlreadyExistsException error) {
                if (Files.isSymbolicLink(directory) ||
                        !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
                    throw new IOException("output directory changed while creating it", error);
                }
            }
        }
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("output path component is not a directory");
        }
        return directory;
    }

    private static void move(Path source, Path destination) throws IOException {
        try {
            Files.move(source, destination, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        }
        catch (AtomicMoveNotSupportedException error) {
            Files.move(source, destination, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    @FunctionalInterface
    interface WriteAction {
        void write(BufferedWriter writer) throws IOException, CancelledException;
    }
}
