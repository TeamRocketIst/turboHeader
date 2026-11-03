import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

public class GhidraGradle {
    private static final int PROPERTY_LIMIT = 65536;
    private static final String DOWNLOAD_ROOT = "https://services.gradle.org/distributions/gradle-";

    public static void main(String[] args) {
        try {
            System.exit(run(args));
        }
        catch (Exception error) {
            System.err.println("TurboHeader build: " + error.getMessage());
            System.exit(1);
        }
    }

    static int run(String[] args) throws Exception {
        Path project = Path.of(args[0]).toAbsolutePath().normalize();
        var arguments = new ArrayList<>(Arrays.asList(args).subList(1, args.length));
        Path sdk = sdkPath(System.getenv("GHIDRA_INSTALL_DIR"), arguments);
        Properties application = readProperties(sdk.resolve("Ghidra/application.properties"));
        int compiler = javaVersion(application, "application.java.compiler");
        int minimum = Math.max(compiler, javaVersion(application, "application.java.min"));
        if (arguments.equals(List.of("--ghidra-java-version"))) {
            System.out.println(minimum);
            return 0;
        }
        if (Runtime.version().feature() < minimum) {
            throw new IOException("This Ghidra SDK requires JDK " + minimum + " or later; set JAVA_HOME to that JDK.");
        }
        if (!application.getProperty("application.java.max", "").isBlank() &&
                Runtime.version().feature() > javaVersion(application, "application.java.max")) {
            throw new IOException("This Java version is newer than the selected Ghidra SDK supports.");
        }
        Path javaHome = Path.of(System.getProperty("java.home"));
        String executable = System.getProperty("os.name").startsWith("Windows") ? ".exe" : "";
        if (!Files.isRegularFile(javaHome.resolve("bin/javac" + executable))) {
            throw new IOException("A full JDK is required, not just a Java runtime; set JAVA_HOME to the JDK.");
        }
        Path workingDirectory = Path.of("").toAbsolutePath();
        if (!arguments.isEmpty() && arguments.getFirst().equals("--ghidra-native")) {
            arguments.removeFirst();
            workingDirectory = sdk.resolve("support/gradle");
        }
        Properties sdkWrapper = readProperties(sdk.resolve("support/gradle/gradle-wrapper.properties"));
        String version = distributionVersion(sdkWrapper.getProperty("distributionUrl", ""));
        Properties pins = readProperties(project.resolve("gradle/checksums.properties"));
        String checksum = pins.getProperty(version, sdkWrapper.getProperty("distributionSha256Sum"));
        if (checksum == null) {
            System.out.println("TurboHeader build: checking the official Gradle " + version + " checksum...");
            checksum = fetchChecksum(URI.create(DOWNLOAD_ROOT + version + "-bin.zip.sha256"));
        }
        requireChecksum(checksum);
        Properties wrapper = wrapperProperties(version, checksum);
        Path temporary = Files.createTempDirectory("turboheader-gradle-");
        Path jar = temporary.resolve("gradle-wrapper.jar");
        Path properties = temporary.resolve("gradle-wrapper.properties");
        try {
            Files.copy(project.resolve("gradle/wrapper/gradle-wrapper.jar"), jar);
            try (var output = Files.newOutputStream(properties)) {
                wrapper.store(output, "Selected Ghidra SDK build requirements");
            }
            var command = new ArrayList<>(List.of(javaHome.resolve("bin/java" + executable).toString()));
            command.addAll(java.lang.management.ManagementFactory.getRuntimeMXBean().getInputArguments());
            command.addAll(List.of("-jar", jar.toString()));
            command.addAll(arguments);
            System.out.println("TurboHeader build: Gradle " + version + ", JDK " + Runtime.version().feature() + ".");
            Process process = new ProcessBuilder(command).directory(workingDirectory.toFile()).inheritIO().start();
            Thread shutdown = new Thread(process::destroy, "gradle-shutdown");
            Runtime.getRuntime().addShutdownHook(shutdown);
            try {
                return process.waitFor();
            }
            finally {
                process.destroy();
                Runtime.getRuntime().removeShutdownHook(shutdown);
            }
        }
        finally {
            Files.deleteIfExists(properties);
            Files.deleteIfExists(jar);
            Files.deleteIfExists(temporary);
        }
    }

    static Path sdkPath(String environment, List<String> arguments) throws IOException {
        String property = null;
        for (int i = 0; i < arguments.size(); i++) {
            String value = arguments.get(i);
            if (value.equals("-P") || value.equals("--project-prop")) {
                if (++i == arguments.size()) {
                    throw new IOException("Missing Gradle project property.");
                }
                value = arguments.get(i);
            }
            else if (value.startsWith("-P")) {
                value = value.substring(2);
            }
            else if (value.startsWith("--project-prop=")) {
                value = value.substring("--project-prop=".length());
            }
            else {
                continue;
            }
            if (value.startsWith("GHIDRA_INSTALL_DIR=")) {
                if (property != null) {
                    throw new IOException("Pass GHIDRA_INSTALL_DIR only once.");
                }
                property = value.substring("GHIDRA_INSTALL_DIR=".length());
            }
        }
        String selected = environment == null || environment.isEmpty() ? property : environment;
        if (selected == null || selected.isBlank()) {
            throw new IOException("Set GHIDRA_INSTALL_DIR to the Ghidra installation root.");
        }
        Path sdk = Path.of(selected).toAbsolutePath().normalize();
        if (!Files.isRegularFile(sdk.resolve("support/buildExtension.gradle"))) {
            throw new IOException("GHIDRA_INSTALL_DIR must contain Ghidra/application.properties and support/buildExtension.gradle.");
        }
        return sdk;
    }

    static int javaVersion(Properties properties, String key) throws IOException {
        String value = properties.getProperty(key, "");
        if (value.length() < 1 || value.length() > 2 || !value.chars().allMatch(c -> c >= '0' && c <= '9')) {
            throw new IOException("Missing or invalid Ghidra requirement: " + key);
        }
        int version = Integer.parseInt(value);
        if (version < 21) {
            throw new IOException("Unsupported Ghidra Java requirement: " + value);
        }
        return version;
    }

    static Properties readProperties(Path path) throws IOException {
        byte[] bytes;
        try (var input = Files.newInputStream(path)) {
            bytes = input.readNBytes(PROPERTY_LIMIT + 1);
        }
        if (bytes.length > PROPERTY_LIMIT) {
            throw new IOException("Build properties exceed the size limit: " + path.getFileName());
        }
        Properties properties = new Properties() {
            @Override
            public synchronized Object put(Object key, Object value) {
                if (containsKey(key)) {
                    throw new IllegalArgumentException("Duplicate build property: " + key);
                }
                return super.put(key, value);
            }
        };
        properties.load(new ByteArrayInputStream(bytes));
        return properties;
    }

    static String distributionVersion(String url) throws IOException {
        if (!url.startsWith(DOWNLOAD_ROOT) || !url.endsWith("-bin.zip")) {
            throw new IOException("Ghidra must select an official Gradle binary distribution over HTTPS.");
        }
        String version = url.substring(DOWNLOAD_ROOT.length(), url.length() - "-bin.zip".length());
        String[] parts = version.split("\\.", -1);
        if (version.length() > 24 || parts.length < 2 || parts.length > 3) {
            throw new IOException("Invalid Gradle release version.");
        }
        for (String part : parts) {
            if (part.isEmpty() || !part.chars().allMatch(c -> c >= '0' && c <= '9')) {
                throw new IOException("Invalid Gradle release version.");
            }
        }
        return version;
    }

    static void requireChecksum(String checksum) throws IOException {
        if (checksum.length() != 64 || !checksum.chars().allMatch(c ->
                (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            throw new IOException("Invalid Gradle SHA-256 checksum.");
        }
    }

    static Properties wrapperProperties(String version, String checksum) throws IOException {
        distributionVersion(DOWNLOAD_ROOT + version + "-bin.zip");
        requireChecksum(checksum);
        var properties = new Properties();
        properties.setProperty("distributionUrl", DOWNLOAD_ROOT + version + "-bin.zip");
        properties.setProperty("distributionSha256Sum", checksum);
        properties.setProperty("distributionBase", "GRADLE_USER_HOME");
        properties.setProperty("distributionPath", "wrapper/dists");
        properties.setProperty("zipStoreBase", "GRADLE_USER_HOME");
        properties.setProperty("zipStorePath", "wrapper/dists");
        properties.setProperty("networkTimeout", "30000");
        properties.setProperty("validateDistributionUrl", "true");
        return properties;
    }

    static String fetchChecksum(URI uri) throws IOException {
        for (int redirects = 0; redirects < 4; redirects++) {
            if (!"https".equals(uri.getScheme()) || uri.getUserInfo() != null || uri.getPort() != -1 ||
                    !List.of("services.gradle.org", "downloads.gradle.org").contains(uri.getHost())) {
                throw new IOException("Unexpected Gradle checksum host.");
            }
            var connection = (HttpURLConnection) uri.toURL().openConnection();
            connection.setConnectTimeout((int) Duration.ofSeconds(15).toMillis());
            connection.setReadTimeout((int) Duration.ofSeconds(15).toMillis());
            connection.setInstanceFollowRedirects(false);
            try {
                int status = connection.getResponseCode();
                if (status == 301 || status == 302 || status == 307 || status == 308) {
                    String location = connection.getHeaderField("Location");
                    if (location == null) {
                        throw new IOException("Gradle checksum redirect has no location.");
                    }
                    uri = uri.resolve(location);
                    continue;
                }
                if (status != 200) {
                    throw new IOException("Cannot verify the Gradle checksum (HTTP " + status + ").");
                }
                try (var input = connection.getInputStream()) {
                    byte[] bytes = input.readNBytes(129);
                    if (bytes.length > 128) {
                        throw new IOException("Gradle checksum response exceeds the size limit.");
                    }
                    String checksum = new String(bytes, StandardCharsets.US_ASCII).strip();
                    requireChecksum(checksum);
                    return checksum;
                }
            }
            finally {
                connection.disconnect();
            }
        }
        throw new IOException("Too many Gradle checksum redirects.");
    }
}
