package turboheader.il2cpp;

import java.io.BufferedWriter;
import java.io.IOException;

import ghidra.program.model.listing.Function;

final class Il2CppExportText {
    private Il2CppExportText() {
    }

    static String functionName(Function function) {
        var symbol = function.getSymbol();
        return singleLine(symbol == null ? function.getName() : symbol.getName(true));
    }

    static String singleLine(String value) {
        StringBuilder result = new StringBuilder(value.length());
        for (int offset = 0; offset < value.length();) {
            int codePoint = value.codePointAt(offset);
            offset += Character.charCount(codePoint);
            if (Character.isISOControl(codePoint) ||
                    Character.getType(codePoint) == Character.LINE_SEPARATOR ||
                    Character.getType(codePoint) == Character.PARAGRAPH_SEPARATOR) {
                result.append(' ');
            }
            else {
                result.appendCodePoint(codePoint);
            }
        }
        return result.toString();
    }

    static void line(BufferedWriter writer, String value) throws IOException {
        writer.write(value);
        writer.write('\n');
    }
}
