package turboheader.il2cpp;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

final class NativeLibraryLoader {
    private static volatile boolean loaded;

    private NativeLibraryLoader() {
    }

    static synchronized void load() {
        if (loaded) {
            return;
        }

        List<String> failures = new ArrayList<>();
        String explicit = System.getProperty("turboheader.il2cpp.native");
        if (explicit == null || explicit.isBlank()) {
            explicit = System.getenv("TURBOHEADER_IL2CPP_NATIVE");
        }
        if (explicit != null && !explicit.isBlank()) {
            tryLoad(Path.of(explicit), failures);
            if (loaded) {
                return;
            }
        }

        String platform = platformDirectory();
        String library = System.mapLibraryName("turboheader_il2cpp");
        try {
            URI location = NativeLibraryLoader.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI();
            Path codePath = Path.of(location).toAbsolutePath();
            Path base = Files.isDirectory(codePath) ? codePath : codePath.getParent();
            if (base != null) {
                tryLoad(base.resolve("os").resolve(platform).resolve(library), failures);
                tryLoad(base.resolve("..").resolve("os").resolve(platform).resolve(library).normalize(), failures);
                if (loaded) {
                    return;
                }
            }
        }
        catch (Exception e) {
            failures.add("code-source lookup: " + e.getMessage());
        }

        throw new UnsatisfiedLinkError(
                "TurboHeader extension is missing its native library for " + platform + " (" + library + "). " +
                "Rebuild or reinstall the complete extension. Attempts: " +
                String.join(" | ", failures));
    }

    private static void tryLoad(Path candidate, List<String> failures) {
        if (candidate == null || !Files.isRegularFile(candidate)) {
            if (candidate != null) {
                failures.add(candidate + ": not found");
            }
            return;
        }
        try {
            System.load(candidate.toAbsolutePath().toString());
            loaded = true;
        }
        catch (UnsatisfiedLinkError e) {
            failures.add(candidate + ": " + e.getMessage());
        }
    }

    static String platformDirectory() {
        String os = System.getProperty("os.name", "unknown").toLowerCase(Locale.ROOT);
        String arch = System.getProperty("os.arch", "unknown").toLowerCase(Locale.ROOT);
        String osPart = os.contains("win") ? "win" : os.contains("mac") || os.contains("darwin") ? "mac" : "linux";
        String archPart = switch (arch) {
            case "amd64", "x86_64" -> "x86_64";
            case "aarch64", "arm64" -> "aarch64";
            default -> arch.replaceAll("[^a-z0-9_]+", "_");
        };
        return osPart + "_" + archPart;
    }
}
