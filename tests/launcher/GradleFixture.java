import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Properties;

public class GradleFixture {
    public static void main(String[] args) throws Exception {
        Path jar = Path.of(GradleFixture.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        Properties properties = new Properties();
        try (var input = java.nio.file.Files.newInputStream(jar.resolveSibling("gradle-wrapper.properties"))) {
            properties.load(input);
        }
        System.out.println("directory=" + Path.of("").toAbsolutePath());
        System.out.println("checksum=" + properties.getProperty("distributionSha256Sum"));
        for (String arg : args) {
            System.out.println("argument=" + Base64.getEncoder().encodeToString(arg.getBytes(StandardCharsets.UTF_8)));
            if (arg.equals("--fixture-fail")) {
                System.exit(23);
            }
        }
    }
}
