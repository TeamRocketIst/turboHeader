package turboheader.il2cpp;

import java.io.IOException;

public enum Il2CppExportScope {
    WHITELIST,
    BLACKLIST,
    ALL;

    public static Il2CppExportScope parse(String value) throws IOException {
        return switch (value) {
            case "whitelist" -> WHITELIST;
            case "blacklist" -> BLACKLIST;
            case "all" -> ALL;
            default -> throw new IOException("unknown export scope: " + value);
        };
    }
}
