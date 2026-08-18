package turboheader.il2cpp;

import java.util.ArrayList;
import java.util.List;

/** Stores an additive assembly identity in a Ghidra function comment. */
public final class MethodAssemblyIdentity {
    public static final String PREFIX = "TurboHeader assembly: ";

    private MethodAssemblyIdentity() {
    }

    public static String read(String comment) {
        if (comment == null) {
            return null;
        }
        for (String line : comment.lines().toList()) {
            if (line.startsWith(PREFIX)) {
                String assembly = line.substring(PREFIX.length()).trim();
                return assembly.isEmpty() ? null : assembly;
            }
        }
        return null;
    }

    public static String write(String comment, String assembly) {
        String value = assembly == null ? "" : assembly.trim();
        if (value.isEmpty() || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
            throw new IllegalArgumentException("invalid assembly identity");
        }
        List<String> lines = new ArrayList<>();
        if (comment != null) {
            for (String line : comment.lines().toList()) {
                if (!line.startsWith(PREFIX)) {
                    lines.add(line);
                }
            }
        }
        lines.add(PREFIX + value);
        return String.join("\n", lines);
    }
}
