package turboheader.il2cpp.decompile;

import java.nio.file.Path;
import java.util.List;

import turboheader.il2cpp.Il2CppClassCatalog;
import turboheader.il2cpp.metadata.MethodAssemblyIdentity;

public final class Il2CppFunctionMatcherTest {
    private Il2CppFunctionMatcherTest() {
    }

    public static void main(String[] args) {
        longestClassIdentityWins();
        assemblyIdentityResolvesDuplicates();
        assemblyMismatchIsSkipped();
        ambiguityIsReported();
        tokenBoundariesPreventSubstringMatches();
        punctuationIsNormalized();
        exactCaseResolvesDistinctClasses();
        caseInsensitiveFallbackPreservesCompatibility();
        caseInsensitiveFallbackRemainsAmbiguous();
        functionsAreOrderedByUnsignedAddress();
        System.out.println("IL2CPP function matcher tests passed");
    }

    private static void longestClassIdentityWins() {
        var shortName = entry("Game", "Actor.cs");
        var fullName = entry("Game", "World/Core/Actor.cs");
        var function = function(16, "World_Core_Actor__Tick");

        var result = Il2CppFunctionMatcher.match(List.of(shortName, fullName), List.of(function));
        check(result.functionsByClass().get(shortName).isEmpty(), "short candidate rejected");
        check(result.functionsByClass().get(fullName).equals(List.of(function)),
                "longest candidate selected");
    }

    private static void assemblyIdentityResolvesDuplicates() {
        var first = entry("Game.One", "Shared/Actor.cs");
        var second = entry("Game.Two", "Shared/Actor.cs");
        String comment = MethodAssemblyIdentity.write(null, "Game.Two.dll");
        var function = function(20, "Shared_Actor__Run", comment);

        var result = Il2CppFunctionMatcher.match(List.of(first, second), List.of(function));
        check(result.functionsByClass().get(first).isEmpty(), "wrong assembly rejected");
        check(result.functionsByClass().get(second).equals(List.of(function)),
                "assembly identity selected");
        check(result.assemblyAmbiguitiesResolved() == 1, "resolved ambiguity count");
    }

    private static void assemblyMismatchIsSkipped() {
        var entry = entry("Game.One", "Actor.cs");
        String comment = MethodAssemblyIdentity.write(null, "Game.Two");
        var result = Il2CppFunctionMatcher.match(
                List.of(entry), List.of(function(24, "Actor__Run", comment)));

        check(result.functionsByClass().get(entry).isEmpty(), "mismatch rejected");
        check(result.assemblyMismatchesSkipped() == 1, "mismatch count");
    }

    private static void ambiguityIsReported() {
        var first = entry("Game.One", "Shared/Actor.cs");
        var second = entry("Game.Two", "Shared/Actor.cs");
        var result = Il2CppFunctionMatcher.match(
                List.of(first, second), List.of(function(28, "Shared_Actor__Run")));

        check(result.matchedFunctions() == 0, "ambiguous function skipped");
        check(result.ambiguities().size() == 1, "ambiguity recorded");
        check(result.ambiguities().get(0).classes().equals(
                List.of("Game.One/Shared/Actor", "Game.Two/Shared/Actor")),
                "ambiguity candidates");
    }

    private static void tokenBoundariesPreventSubstringMatches() {
        var entry = entry("Game", "a.cs");
        var result = Il2CppFunctionMatcher.match(
                List.of(entry), List.of(function(32, "Data__Run")));

        check(result.matchedFunctions() == 0, "one-letter substring rejected");
    }

    private static void punctuationIsNormalized() {
        var entry = entry("Game", "Collections/Box`1.cs");
        var function = function(36, "Collections.Box`1__Open");
        var result = Il2CppFunctionMatcher.match(List.of(entry), List.of(function));

        check(result.functionsByClass().get(entry).equals(List.of(function)),
                "punctuated class matched");
        check(Il2CppFunctionMatcher.normalizeSymbol("Area::<Actor>").equals("area_actor"),
                "symbol normalization");
    }

    private static void exactCaseResolvesDistinctClasses() {
        var upper = entry("Game", "U.cs");
        var lower = entry("Game", "u.cs");
        var upperFunction = function(40, "U__Start");
        var lowerFunction = function(44, "u__Stop");

        var result = Il2CppFunctionMatcher.match(
                List.of(upper, lower), List.of(lowerFunction, upperFunction));
        check(result.functionsByClass().get(upper).equals(List.of(upperFunction)),
                "uppercase class selected");
        check(result.functionsByClass().get(lower).equals(List.of(lowerFunction)),
                "lowercase class selected");
        check(result.ambiguities().isEmpty(), "exact-case matches are unambiguous");
    }

    private static void caseInsensitiveFallbackPreservesCompatibility() {
        var entry = entry("Game", "PlayerController.cs");
        var function = function(48, "playercontroller__Update");

        var result = Il2CppFunctionMatcher.match(List.of(entry), List.of(function));
        check(result.functionsByClass().get(entry).equals(List.of(function)),
                "case-insensitive fallback matched");
    }

    private static void caseInsensitiveFallbackRemainsAmbiguous() {
        var titleCase = entry("Game", "Actor.cs");
        var lowerCase = entry("Game", "actor.cs");
        var function = function(52, "ACTOR__Update");

        var result = Il2CppFunctionMatcher.match(
                List.of(titleCase, lowerCase), List.of(function));
        check(result.matchedFunctions() == 0, "ambiguous fallback skipped");
        check(result.ambiguities().size() == 1, "fallback ambiguity recorded");
    }

    private static void functionsAreOrderedByUnsignedAddress() {
        var entry = entry("Game", "Actor.cs");
        var later = function(64, "Actor__Late");
        var earlier = function(56, "Actor__Early");
        var result = Il2CppFunctionMatcher.match(List.of(entry), List.of(later, earlier));

        check(result.functionsByClass().get(entry).equals(List.of(earlier, later)),
                "function address order");
        check(result.scannedFunctions() == 2, "scanned count");
        check(result.matchedFunctions() == 2, "matched count");
    }

    private static Il2CppClassCatalog.ClassEntry entry(String assembly, String relative) {
        return new Il2CppClassCatalog.ClassEntry(
                assembly, relative, Path.of("synthetic", assembly, relative));
    }

    private static Il2CppFunctionMatcher.FunctionIdentity function(long address, String name) {
        return function(address, name, null);
    }

    private static Il2CppFunctionMatcher.FunctionIdentity function(
            long address, String name, String comment) {
        return new Il2CppFunctionMatcher.FunctionIdentity(address, name, name, comment);
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
