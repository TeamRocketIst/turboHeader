package turboheader.il2cpp;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Parses the restricted C prototypes stored in IL2CPP script.json files. */
public final class CFunctionSignatureParser {
    public record Parameter(String type, String name) {
        public Parameter {
            if (type == null || type.isBlank()) {
                throw new IllegalArgumentException("parameter type is empty");
            }
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("parameter name is empty");
            }
        }
    }

    public record ParsedSignature(String returnType, String functionName, List<Parameter> parameters,
            boolean varArgs, int duplicateNamesRepaired) {
        public ParsedSignature {
            if (returnType == null || returnType.isBlank()) {
                throw new IllegalArgumentException("return type is empty");
            }
            if (functionName == null || functionName.isBlank()) {
                throw new IllegalArgumentException("function name is empty");
            }
            parameters = List.copyOf(parameters);
        }
    }

    private record Identifier(int start, int end) {
    }

    private record ParsedParameter(String type, String name) {
    }

    private CFunctionSignatureParser() {
    }

    public static ParsedSignature parse(String declaration) {
        if (declaration == null) {
            throw new IllegalArgumentException("signature is null");
        }

        String text = declaration.trim();
        if (text.endsWith(";")) {
            text = text.substring(0, text.length() - 1).trim();
        }
        if (text.isEmpty()) {
            throw new IllegalArgumentException("signature is empty");
        }

        int parametersStart = firstTopLevel(text, '(');
        if (parametersStart < 0) {
            throw new IllegalArgumentException("signature has no parameter list: " + declaration);
        }
        int parametersEnd = matchingClose(text, parametersStart, '(', ')');
        if (!text.substring(parametersEnd + 1).isBlank()) {
            throw new IllegalArgumentException("unexpected text after parameter list: " + declaration);
        }

        String head = text.substring(0, parametersStart).trim();
        Identifier functionName = lastIdentifier(head);
        if (functionName == null || !head.substring(functionName.end()).isBlank()) {
            throw new IllegalArgumentException("invalid function declarator: " + declaration);
        }
        String returnType = head.substring(0, functionName.start()).trim();
        if (returnType.isEmpty()) {
            throw new IllegalArgumentException("signature has no return type: " + declaration);
        }

        List<String> parts = splitTopLevel(
                text.substring(parametersStart + 1, parametersEnd), ',');
        List<Parameter> parameters = new ArrayList<>();
        Set<String> names = new HashSet<>();
        boolean varArgs = false;
        int duplicateNamesRepaired = 0;

        if (parts.size() == 1 && parts.get(0).isBlank()) {
            parts = List.of();
        }
        if (parts.size() == 1 && parts.get(0).trim().equals("void")) {
            parts = List.of();
        }

        for (int i = 0; i < parts.size(); i++) {
            String part = parts.get(i).trim();
            if (part.isEmpty()) {
                throw new IllegalArgumentException("empty parameter in: " + declaration);
            }
            if (part.equals("...")) {
                if (varArgs || i != parts.size() - 1) {
                    throw new IllegalArgumentException("varargs must appear once and last: " + declaration);
                }
                varArgs = true;
                continue;
            }

            ParsedParameter parsed = parseParameter(part);
            String preferred = parsed.name();
            if (preferred == null || preferred.isBlank()) {
                preferred = "arg" + parameters.size();
            }
            String name = allocateName(preferred, names);
            if (!name.equals(preferred)) {
                duplicateNamesRepaired++;
            }
            parameters.add(new Parameter(parsed.type(), name));
        }

        return new ParsedSignature(returnType, head.substring(functionName.start(), functionName.end()),
                parameters, varArgs, duplicateNamesRepaired);
    }

    private static ParsedParameter parseParameter(String declaration) {
        ParsedParameter functionPointer = parseFunctionPointerParameter(declaration);
        if (functionPointer != null) {
            return functionPointer;
        }

        int arrayStart = firstTopLevel(declaration, '[');
        if (arrayStart >= 0) {
            String prefix = declaration.substring(0, arrayStart).trim();
            ParsedParameter base = parsePlainParameter(prefix);
            if (base.name() != null) {
                return new ParsedParameter(
                        base.type() + declaration.substring(arrayStart).trim(), base.name());
            }
        }
        return parsePlainParameter(declaration);
    }

    private static ParsedParameter parseFunctionPointerParameter(String declaration) {
        for (int open = 0; open < declaration.length(); open++) {
            if (declaration.charAt(open) != '(') {
                continue;
            }
            int cursor = skipWhitespace(declaration, open + 1);
            if (cursor >= declaration.length() || declaration.charAt(cursor) != '*') {
                continue;
            }
            cursor = skipWhitespace(declaration, cursor + 1);
            if (cursor >= declaration.length() || !isIdentifierStart(declaration.charAt(cursor))) {
                continue;
            }
            int nameEnd = identifierEnd(declaration, cursor);
            int close = skipWhitespace(declaration, nameEnd);
            if (close >= declaration.length() || declaration.charAt(close) != ')') {
                continue;
            }

            String before = declaration.substring(0, cursor);
            String after = declaration.substring(nameEnd);
            String type = trimWhitespaceBeforeClosingParen(before + after);
            return new ParsedParameter(type, declaration.substring(cursor, nameEnd));
        }
        return null;
    }

    private static ParsedParameter parsePlainParameter(String declaration) {
        Identifier candidate = lastIdentifier(declaration);
        if (candidate == null || !declaration.substring(candidate.end()).isBlank()) {
            return new ParsedParameter(declaration.trim(), null);
        }

        String before = declaration.substring(0, candidate.start()).trim();
        String word = declaration.substring(candidate.start(), candidate.end());
        if (before.isEmpty() || isTypeWord(word) || containsOnlyQualifiersOrTag(before)) {
            return new ParsedParameter(declaration.trim(), null);
        }
        return new ParsedParameter(before, word);
    }

    private static String allocateName(String preferred, Set<String> used) {
        if (used.add(preferred)) {
            return preferred;
        }
        for (int suffix = 1; ; suffix++) {
            String candidate = preferred + "_" + suffix;
            if (used.add(candidate)) {
                return candidate;
            }
        }
    }

    private static List<String> splitTopLevel(String text, char delimiter) {
        List<String> result = new ArrayList<>();
        int parentheses = 0;
        int brackets = 0;
        int braces = 0;
        int start = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '(' -> parentheses++;
                case ')' -> parentheses--;
                case '[' -> brackets++;
                case ']' -> brackets--;
                case '{' -> braces++;
                case '}' -> braces--;
                default -> {
                }
            }
            if (parentheses < 0 || brackets < 0 || braces < 0) {
                throw new IllegalArgumentException("unbalanced parameter declaration: " + text);
            }
            if (c == delimiter && parentheses == 0 && brackets == 0 && braces == 0) {
                result.add(text.substring(start, i));
                start = i + 1;
            }
        }
        if (parentheses != 0 || brackets != 0 || braces != 0) {
            throw new IllegalArgumentException("unbalanced parameter declaration: " + text);
        }
        result.add(text.substring(start));
        return result;
    }

    private static int firstTopLevel(String text, char wanted) {
        int parentheses = 0;
        int brackets = 0;
        int braces = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == wanted && parentheses == 0 && brackets == 0 && braces == 0) {
                return i;
            }
            switch (c) {
                case '(' -> parentheses++;
                case ')' -> parentheses--;
                case '[' -> brackets++;
                case ']' -> brackets--;
                case '{' -> braces++;
                case '}' -> braces--;
                default -> {
                }
            }
            if (parentheses < 0 || brackets < 0 || braces < 0) {
                throw new IllegalArgumentException("unbalanced declaration: " + text);
            }
        }
        return -1;
    }

    private static int matchingClose(String text, int open, char opening, char closing) {
        int depth = 0;
        for (int i = open; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == opening) {
                depth++;
            }
            else if (c == closing && --depth == 0) {
                return i;
            }
        }
        throw new IllegalArgumentException("unbalanced parameter list: " + text);
    }

    private static Identifier lastIdentifier(String text) {
        for (int i = text.length() - 1; i >= 0; i--) {
            if (!isIdentifierPart(text.charAt(i))) {
                continue;
            }
            int end = i + 1;
            while (i >= 0 && isIdentifierPart(text.charAt(i))) {
                i--;
            }
            int start = i + 1;
            if (isIdentifierStart(text.charAt(start))) {
                return new Identifier(start, end);
            }
        }
        return null;
    }

    private static int identifierEnd(String text, int start) {
        int end = start + 1;
        while (end < text.length() && isIdentifierPart(text.charAt(end))) {
            end++;
        }
        return end;
    }

    private static int skipWhitespace(String text, int start) {
        int cursor = start;
        while (cursor < text.length() && Character.isWhitespace(text.charAt(cursor))) {
            cursor++;
        }
        return cursor;
    }

    private static boolean isIdentifierStart(char c) {
        return c == '_' || c == '$' || Character.isLetter(c);
    }

    private static boolean isIdentifierPart(char c) {
        return isIdentifierStart(c) || Character.isDigit(c);
    }

    private static boolean isTypeWord(String word) {
        return switch (word) {
            case "void", "bool", "char", "short", "int", "long", "signed", "unsigned",
                    "float", "double", "const", "volatile", "restrict", "struct", "union",
                    "enum" -> true;
            default -> false;
        };
    }

    private static boolean containsOnlyQualifiersOrTag(String text) {
        int start = 0;
        boolean found = false;
        while (start < text.length()) {
            start = skipWhitespace(text, start);
            if (start == text.length()) {
                break;
            }
            if (!isIdentifierStart(text.charAt(start))) {
                return false;
            }
            int end = identifierEnd(text, start);
            String word = text.substring(start, end);
            if (!word.equals("const") && !word.equals("volatile") && !word.equals("restrict") &&
                    !word.equals("struct") && !word.equals("union") && !word.equals("enum")) {
                return false;
            }
            found = true;
            start = end;
        }
        return found;
    }

    private static String trimWhitespaceBeforeClosingParen(String text) {
        StringBuilder result = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == ')') {
                while (!result.isEmpty() && Character.isWhitespace(result.charAt(result.length() - 1))) {
                    result.setLength(result.length() - 1);
                }
            }
            result.append(c);
        }
        return result.toString().trim();
    }
}
