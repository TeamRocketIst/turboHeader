// Verifies that script.json prototypes survived the real Ghidra API import.
// @category Data Types

import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import turboheader.il2cpp.CFunctionSignatureParser;
import turboheader.il2cpp.MethodAssemblyIdentity;
import turboheader.il2cpp.ScriptMethodReader;

public class VerifyTurboHeaderMethods extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        require(args.length == 1, "expected: script.json");

        var methods = ScriptMethodReader.read(Path.of(args[0]));
        int repairedNames = 0;
        int preservedMethodInfoComments = 0;
        for (var method : methods) {
            monitor.checkCancelled();
            var parsed = CFunctionSignatureParser.parse(method.signature());
            Function function = currentProgram.getFunctionManager().getFunctionAt(
                    currentProgram.getImageBase().add(method.address()));
            require(function != null, "missing function at 0x" + Long.toHexString(method.address()));
            if (method.assembly() != null) {
                require(method.assembly().equals(MethodAssemblyIdentity.read(function.getComment())),
                        "assembly identity differs at 0x" + Long.toHexString(method.address()));
            }

            Parameter[] imported = Arrays.stream(function.getParameters())
                    .filter(parameter -> !parameter.isAutoParameter())
                    .toArray(Parameter[]::new);
            require(imported.length == parsed.parameters().size(),
                    "parameter count differs at 0x" + Long.toHexString(method.address()));
            Set<String> names = new HashSet<>();
            for (int i = 0; i < imported.length; i++) {
                String expectedName = parsed.parameters().get(i).name();
                require(expectedName.equals(imported[i].getName()),
                        "parameter name differs at 0x" + Long.toHexString(method.address()) +
                        ": expected " + expectedName + ", got " + imported[i].getName());
                require(names.add(imported[i].getName()),
                        "duplicate imported parameter at 0x" + Long.toHexString(method.address()));

                String originalType = parsed.parameters().get(i).type();
                if (isSpecializedMethodInfo(originalType)) {
                    require(("Original IL2CPP parameter type: " + originalType)
                            .equals(imported[i].getComment()),
                            "specialized MethodInfo provenance missing at 0x" +
                            Long.toHexString(method.address()));
                    preservedMethodInfoComments++;
                }
            }
            repairedNames += parsed.duplicateNamesRepaired();
        }

        println(String.format(
                "TurboHeader method verification passed: %,d methods, %,d repaired duplicate names, " +
                "%,d specialized MethodInfo comments",
                methods.size(), repairedNames, preservedMethodInfoComments));
    }

    private static boolean isSpecializedMethodInfo(String declaration) {
        String text = declaration.trim();
        if (text.startsWith("const") && text.length() > 5 &&
                Character.isWhitespace(text.charAt(5))) {
            text = text.substring(6).trim();
        }
        while (text.endsWith("*")) {
            text = text.substring(0, text.length() - 1).trim();
        }
        if (!text.startsWith("MethodInfo_") || text.length() == "MethodInfo_".length()) {
            return false;
        }
        for (int i = "MethodInfo_".length(); i < text.length(); i++) {
            if (Character.digit(text.charAt(i), 16) < 0) {
                return false;
            }
        }
        return true;
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
