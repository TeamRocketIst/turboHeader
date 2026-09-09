package turboheader.il2cpp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class Il2CppFunctionMatcher {
    private Il2CppFunctionMatcher() {
    }

    public static MatchResult match(List<Il2CppClassCatalog.ClassEntry> classes,
            List<FunctionIdentity> functions) {
        Objects.requireNonNull(classes, "classes");
        Objects.requireNonNull(functions, "functions");

        CandidateIndex index = CandidateIndex.create(classes);
        Map<Il2CppClassCatalog.ClassEntry, List<FunctionIdentity>> matches =
                new LinkedHashMap<>();
        for (var entry : classes) {
            matches.put(entry, new ArrayList<>());
        }

        List<FunctionIdentity> orderedFunctions = new ArrayList<>(functions);
        orderedFunctions.sort((left, right) ->
                Long.compareUnsigned(left.entryPoint(), right.entryPoint()));
        List<Ambiguity> ambiguities = new ArrayList<>();
        int resolvedAssemblies = 0;
        int assemblyMismatches = 0;
        int matchedFunctions = 0;

        for (FunctionIdentity function : orderedFunctions) {
            CandidateMatch candidate = index.find(function);
            if (candidate == null) {
                continue;
            }

            List<Il2CppClassCatalog.ClassEntry> possible = candidate.classes();
            String assembly = MethodAssemblyIdentity.read(function.comment());
            if (assembly != null) {
                List<Il2CppClassCatalog.ClassEntry> sameAssembly = possible.stream()
                        .filter(entry -> Il2CppClassSelector.normalizeAssembly(entry.assembly())
                                .equals(Il2CppClassSelector.normalizeAssembly(assembly)))
                        .toList();
                if (sameAssembly.isEmpty()) {
                    assemblyMismatches++;
                    continue;
                }
                if (possible.size() > 1 && sameAssembly.size() == 1) {
                    resolvedAssemblies++;
                }
                possible = sameAssembly;
            }

            if (possible.size() > 1) {
                ambiguities.add(new Ambiguity(function.entryPoint(), function.simpleName(),
                        candidate.key(), possible.stream()
                                .map(Il2CppClassCatalog.ClassEntry::displayName).toList()));
                continue;
            }

            matches.get(possible.get(0)).add(function);
            matchedFunctions++;
        }

        Map<Il2CppClassCatalog.ClassEntry, List<FunctionIdentity>> immutableMatches =
                new LinkedHashMap<>();
        matches.forEach((entry, entries) -> immutableMatches.put(entry, List.copyOf(entries)));
        return new MatchResult(
                Collections.unmodifiableMap(immutableMatches),
                List.copyOf(ambiguities),
                functions.size(),
                matchedFunctions,
                resolvedAssemblies,
                assemblyMismatches);
    }

    static String normalizeSymbol(String value) {
        return normalizeSymbol(value, true);
    }

    private static String normalizeSymbol(String value, boolean foldCase) {
        StringBuilder normalized = new StringBuilder();
        boolean separator = false;
        for (int index = 0; index < value.length();) {
            int codePoint = value.codePointAt(index);
            index += Character.charCount(codePoint);
            if (Character.isLetterOrDigit(codePoint)) {
                normalized.appendCodePoint(foldCase ? Character.toLowerCase(codePoint) : codePoint);
                separator = false;
            }
            else if (!separator && !normalized.isEmpty()) {
                normalized.append('_');
                separator = true;
            }
        }
        int length = normalized.length();
        if (length > 0 && normalized.charAt(length - 1) == '_') {
            normalized.setLength(length - 1);
        }
        return normalized.toString();
    }

    public record FunctionIdentity(long entryPoint, String fullName, String simpleName,
            String comment) {
        public FunctionIdentity {
            Objects.requireNonNull(fullName, "fullName");
            Objects.requireNonNull(simpleName, "simpleName");
            if (fullName.isEmpty() || simpleName.isEmpty()) {
                throw new IllegalArgumentException("function names must not be empty");
            }
        }
    }

    public record Ambiguity(long entryPoint, String functionName, String candidate,
            List<String> classes) {
        public Ambiguity {
            classes = List.copyOf(classes);
        }
    }

    public record MatchResult(
            Map<Il2CppClassCatalog.ClassEntry, List<FunctionIdentity>> functionsByClass,
            List<Ambiguity> ambiguities, int scannedFunctions, int matchedFunctions,
            int assemblyAmbiguitiesResolved, int assemblyMismatchesSkipped) {
    }

    private record Candidate(List<Il2CppClassCatalog.ClassEntry> classes) {
    }

    private record CandidateMatch(String key, List<Il2CppClassCatalog.ClassEntry> classes) {
    }

    private record CandidateIndex(Map<String, Candidate> exactCandidates,
            Map<String, Candidate> foldedCandidates, int maximumTokens) {
        static CandidateIndex create(List<Il2CppClassCatalog.ClassEntry> classes) {
            Map<String, LinkedHashSet<Il2CppClassCatalog.ClassEntry>> exactBuilders =
                    new LinkedHashMap<>();
            Map<String, LinkedHashSet<Il2CppClassCatalog.ClassEntry>> foldedBuilders =
                    new LinkedHashMap<>();
            int maximumTokens = 1;
            for (var entry : classes) {
                for (String rawName : entry.candidateNames()) {
                    String exact = normalizeSymbol(rawName, false);
                    if (exact.isEmpty()) {
                        continue;
                    }
                    String folded = normalizeSymbol(rawName, true);
                    int tokens = tokenCount(exact);
                    maximumTokens = Math.max(maximumTokens, tokens);
                    exactBuilders.computeIfAbsent(exact, unused -> new LinkedHashSet<>())
                            .add(entry);
                    foldedBuilders.computeIfAbsent(folded, unused -> new LinkedHashSet<>())
                            .add(entry);
                }
            }

            return new CandidateIndex(buildCandidates(exactBuilders),
                    buildCandidates(foldedBuilders), maximumTokens);
        }

        CandidateMatch find(FunctionIdentity function) {
            CandidateMatch exact = find(function, exactCandidates, false);
            return exact != null ? exact : find(function, foldedCandidates, true);
        }

        private CandidateMatch find(FunctionIdentity function,
                Map<String, Candidate> candidates, boolean foldCase) {
            List<String> names = new ArrayList<>();
            names.add(function.fullName());
            if (!function.simpleName().equals(function.fullName())) {
                names.add(function.simpleName());
            }

            Candidate best = null;
            String bestKey = null;
            int bestTokens = -1;
            for (String rawName : names) {
                String normalized = normalizeSymbol(rawName, foldCase);
                if (normalized.isEmpty()) {
                    continue;
                }
                String[] tokens = normalized.split("_");
                int limit = Math.min(tokens.length, maximumTokens);
                for (int count = limit; count > 0; count--) {
                    String key = String.join("_", List.of(tokens).subList(0, count));
                    Candidate candidate = candidates.get(key);
                    if (candidate != null && count > bestTokens) {
                        best = candidate;
                        bestKey = key;
                        bestTokens = count;
                        break;
                    }
                }
            }
            return best == null ? null : new CandidateMatch(bestKey, best.classes());
        }

        private static Map<String, Candidate> buildCandidates(
                Map<String, LinkedHashSet<Il2CppClassCatalog.ClassEntry>> builders) {
            Map<String, Candidate> candidates = new LinkedHashMap<>();
            builders.forEach((name, entries) ->
                    candidates.put(name, new Candidate(List.copyOf(entries))));
            return Collections.unmodifiableMap(candidates);
        }

        private static int tokenCount(String value) {
            int count = 1;
            for (int index = 0; index < value.length(); index++) {
                if (value.charAt(index) == '_') {
                    count++;
                }
            }
            return count;
        }
    }

}
