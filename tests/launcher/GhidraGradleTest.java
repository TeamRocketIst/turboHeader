import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLStreamHandler;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;

public class GhidraGradleTest {
    private static int checks;
    private static int responseStatus = 200;
    private static byte[] response = "a".repeat(64).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static String redirect;
    private static int connections;

    public static void main(String[] args) throws Exception {
        String url = "https://services.gradle.org/distributions/gradle-9.8.0-bin.zip";
        require(GhidraGradle.distributionVersion(url).equals("9.8.0"));
        for (String invalid : List.of("http:" + url.substring(6), url + "?a=b",
                url.replace("services.gradle.org", "services.gradle.org.example"),
                url.replace("9.8.0", "../9.8.0"), url.replace("9.8.0", "9..8"),
                url.replace("9.8.0", "9.8-rc-1"), "file:///tmp/gradle-9.8.0-bin.zip")) {
            rejects(() -> GhidraGradle.distributionVersion(invalid));
        }
        String hash = "a".repeat(64);
        var configuration = GhidraGradle.wrapperProperties("9.8.0", hash);
        require(configuration.getProperty("distributionSha256Sum").equals(hash));
        require(configuration.getProperty("distributionUrl").equals(url));
        for (String invalid : List.of("", "a".repeat(63), "a".repeat(65), "g".repeat(64), hash + "\n")) {
            rejects(() -> GhidraGradle.requireChecksum(invalid));
        }
        Properties application = new Properties();
        for (String invalid : List.of("", "0", "17", "025", "25\n", "25;exit", "-1")) {
            application.setProperty("application.java.compiler", invalid);
            rejects(() -> GhidraGradle.javaVersion(application, "application.java.compiler"));
        }
        application.setProperty("application.java.compiler", "25");
        require(GhidraGradle.javaVersion(application, "application.java.compiler") == 25);
        rejects(() -> GhidraGradle.sdkPath(null, List.of()));
        rejects(() -> GhidraGradle.sdkPath(null, List.of("-P")));
        rejects(() -> GhidraGradle.sdkPath(null, List.of("-PGHIDRA_INSTALL_DIR=a", "-PGHIDRA_INSTALL_DIR=b")));
        rejects(() -> GhidraGradle.fetchChecksum(URI.create("http://services.gradle.org/checksum")));
        rejects(() -> GhidraGradle.fetchChecksum(URI.create("https://example.invalid/checksum")));
        rejects(() -> GhidraGradle.fetchChecksum(URI.create("https://user@services.gradle.org/checksum")));
        rejects(() -> GhidraGradle.fetchChecksum(URI.create("https://services.gradle.org:443/checksum")));
        testChecksumResponses();
        Path file = Files.createTempFile("build-properties-", ".properties");
        try {
            Files.writeString(file, "key=value\r\n");
            require(GhidraGradle.readProperties(file).getProperty("key").equals("value"));
            Files.writeString(file, "key=value\nkey=other\n");
            rejects(() -> GhidraGradle.readProperties(file));
            Files.writeString(file, "x".repeat(65537));
            rejects(() -> GhidraGradle.readProperties(file));
        }
        finally {
            Files.delete(file);
        }
        System.out.println("GhidraGradleTest: " + checks + " checks passed");
    }

    private static void testChecksumResponses() throws Exception {
        URL.setURLStreamHandlerFactory(protocol -> protocol.equals("https") ? new URLStreamHandler() {
            @Override
            protected java.net.URLConnection openConnection(URL url) {
                connections++;
                return new HttpURLConnection(url) {
                    @Override public void connect() {}
                    @Override public void disconnect() {}
                    @Override public boolean usingProxy() { return false; }
                    @Override public int getResponseCode() { return responseStatus; }
                    @Override public String getHeaderField(String name) { return redirect; }
                    @Override public InputStream getInputStream() { return new ByteArrayInputStream(response); }
                };
            }
        } : null);
        URI uri = URI.create("https://services.gradle.org/distributions/gradle-9.8.0-bin.zip.sha256");
        require(GhidraGradle.fetchChecksum(uri).equals("a".repeat(64)));
        response = "a".repeat(129).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        rejects(() -> GhidraGradle.fetchChecksum(uri));
        response = "invalid checksum".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        rejects(() -> GhidraGradle.fetchChecksum(uri));
        responseStatus = 404;
        rejects(() -> GhidraGradle.fetchChecksum(uri));
        responseStatus = 302;
        redirect = "https://example.invalid/checksum";
        int before = connections;
        rejects(() -> GhidraGradle.fetchChecksum(uri));
        require(connections == before + 1);
        redirect = "http://services.gradle.org/checksum";
        before = connections;
        rejects(() -> GhidraGradle.fetchChecksum(uri));
        require(connections == before + 1);
        redirect = null;
        rejects(() -> GhidraGradle.fetchChecksum(uri));
        redirect = uri.toString();
        before = connections;
        rejects(() -> GhidraGradle.fetchChecksum(uri));
        require(connections == before + 4);
    }

    private static void require(boolean condition) {
        checks++;
        if (!condition) {
            throw new AssertionError("Build policy check failed");
        }
    }

    private static void rejects(Check action) throws Exception {
        checks++;
        try {
            action.run();
        }
        catch (IOException | IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Invalid build input accepted");
    }

    private interface Check {
        void run() throws Exception;
    }
}
