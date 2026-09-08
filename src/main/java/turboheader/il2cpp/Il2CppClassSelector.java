package turboheader.il2cpp;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public final class Il2CppClassSelector {
    private static final int MAX_RULE_BYTES = 1024 * 1024;
    private static final int MAX_RULES = 4096;
    private static final int MAX_RULE_CHARS = 256;

    private static final List<String> DEFAULT_WHITELIST = List.of(
            "Assembly-CSharp", "Assembly-CSharp-firstpass");

    private static final List<String> BUILTIN_FRAMEWORKS = List.of(
            "__Generated", "AppsFlyer", "Adjust", "AdjustSdk", "Facebook", "Firebase",
            "GameAnalytics", "Singular", "Tenjin", "Kochava", "Branch", "Amplitude",
            "Flurry", "Mixpanel", "Segment", "Bugsnag", "Sentry", "ByteBrew",
            "GoogleMobileAds", "AudienceNetwork", "UnityAds", "IronSource", "AppLovin",
            "MoPub", "Chartboost", "Vungle", "AdColony", "Mintegral", "Pangle", "Fyber",
            "Yodo1", "Tapjoy", "Unity.Advertisement", "BestHTTP", "WebSocketSharp", "Google",
            "protobuf", "Photon", "PlayFab", "Nakama", "Mirror", "Newtonsoft", "LitJson",
            "SimpleJSON", "Sirenix", "OdinSerializer", "Odin", "MessagePack", "ZString",
            "DOTween", "DOTweenPro", "LeanTween", "PrimeTween", "Spine", "Animancer",
            "Cinemachine", "MoreMountains", "FMOD", "Wwise", "ToonyColorsPro",
            "ToonyColorsPro2", "UniTask", "Cysharp", "UniRx", "R3", "Zenject", "Extenject",
            "VContainer", "Rewired", "InControl", "UltEvents", "NaughtyAttributes",
            "SRDebugger", "StompyRobot", "ConsolePro", "ConsoleProDebug", "ConsoleProRemote",
            "IngameDebugConsole", "UniWebView", "Michsky", "Coffee", "MPUIKit", "TMPro",
            "ILRuntime", "Lua", "XLua", "OPS", "GUPS", "Beebyte", "Obfuz", "Mono");

    private static final List<String> AUTOMATIC_FRAMEWORKS = List.of(
            "Unity", "UnityEngine", "mscorlib", "netstandard", "System", "Microsoft");

    private Il2CppClassSelector() {
    }

    public static Selection select(List<Il2CppClassCatalog.ClassEntry> classes,
            Il2CppExportScope scope, List<String> assemblies, List<String> requestedClasses,
            Path frameworkRuleFile) throws IOException {
        Objects.requireNonNull(classes, "classes");
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(assemblies, "assemblies");
        Objects.requireNonNull(requestedClasses, "requestedClasses");

        List<FrameworkRule> rules = scope == Il2CppExportScope.BLACKLIST
                ? frameworkRules(frameworkRuleFile)
                : List.of();
        List<String> selectedAssemblies = assemblies.isEmpty() ? DEFAULT_WHITELIST : assemblies;
        Set<String> assemblySet = normalizeAssemblies(selectedAssemblies);
        boolean allAssemblies = assemblySet.contains("*") || assemblySet.contains("all");
        Set<String> classSet = normalizeClasses(requestedClasses);
        List<Il2CppClassCatalog.ClassEntry> selected = new ArrayList<>();
        Map<String, AssemblyDecision> decisions = new LinkedHashMap<>();

        for (var entry : classes) {
            String key = normalizeAssembly(entry.assembly());
            AssemblyDecision decision = decisions.get(key);
            if (decision == null) {
                decision = decideAssembly(entry.assembly(), scope, assemblySet, allAssemblies, rules);
                decisions.put(key, decision);
            }
            if (decision.included() && matchesClass(entry, classSet)) {
                selected.add(entry);
            }
        }
        return new Selection(List.copyOf(selected),
                Collections.unmodifiableMap(new LinkedHashMap<>(decisions)));
    }

    static boolean matchesFramework(String assembly, String rule) {
        String value = normalizeAssembly(assembly);
        String prefix = normalizeAssembly(rule);
        return !prefix.isEmpty() && (value.equals(prefix) || value.startsWith(prefix + ".") ||
                value.startsWith(prefix + "-"));
    }

    private static AssemblyDecision decideAssembly(String assembly, Il2CppExportScope scope,
            Set<String> whitelist, boolean allAssemblies, List<FrameworkRule> rules) {
        if (scope == Il2CppExportScope.ALL) {
            return new AssemblyDecision(assembly, true, "all-assemblies mode");
        }
        if (scope == Il2CppExportScope.WHITELIST) {
            boolean included = allAssemblies || whitelist.contains(normalizeAssembly(assembly));
            String reason = included ? "selected by whitelist" : "not present in selected assemblies";
            return new AssemblyDecision(assembly, included, reason);
        }

        FrameworkRule match = null;
        for (FrameworkRule rule : rules) {
            if (!matchesFramework(assembly, rule.name())) {
                continue;
            }
            if (match == null || normalizeAssembly(rule.name()).length() >
                    normalizeAssembly(match.name()).length()) {
                match = rule;
            }
        }
        if (match == null) {
            return new AssemblyDecision(assembly, true, "not blacklisted");
        }
        return new AssemblyDecision(assembly, false,
                "matched " + match.source() + " rule '" + match.name() + "'");
    }

    private static boolean matchesClass(Il2CppClassCatalog.ClassEntry entry,
            Set<String> requested) {
        return requested.isEmpty() || entry.selectionKeys().stream().anyMatch(requested::contains);
    }

    private static Set<String> normalizeAssemblies(List<String> values) {
        Set<String> result = new LinkedHashSet<>();
        values.stream().map(Il2CppClassSelector::normalizeAssembly).forEach(result::add);
        return result;
    }

    private static Set<String> normalizeClasses(List<String> values) {
        Set<String> result = new LinkedHashSet<>();
        for (String raw : values) {
            String value = raw.trim().replace('\\', '/').toLowerCase(Locale.ROOT);
            if (value.endsWith(".cpp")) {
                value = value.substring(0, value.length() - 4) + ".cs";
            }
            result.add(value);
            if (value.endsWith(".cs")) {
                String withoutExtension = value.substring(0, value.length() - 3);
                result.add(withoutExtension);
                result.add(withoutExtension.replace('/', '.'));
            }
            else {
                result.add(value.replace('/', '.'));
            }
        }
        return result;
    }

    private static List<FrameworkRule> frameworkRules(Path configured) throws IOException {
        Map<String, FrameworkRule> rules = new LinkedHashMap<>();
        addRules(rules, BUILTIN_FRAMEWORKS, "built-in");
        addRules(rules, AUTOMATIC_FRAMEWORKS, "automatic");
        if (configured != null) {
            addRules(rules, readRuleFile(configured), "configured file");
        }
        return List.copyOf(rules.values());
    }

    private static void addRules(Map<String, FrameworkRule> target, List<String> values,
            String source) {
        for (String value : values) {
            String normalized = normalizeAssembly(value);
            if (!normalized.isEmpty()) {
                target.putIfAbsent(normalized, new FrameworkRule(value.trim(), source));
            }
        }
    }

    private static List<String> readRuleFile(Path path) throws IOException {
        if (Files.isSymbolicLink(path) ||
                !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("framework rule path must identify a regular file");
        }
        Set<OpenOption> options = Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
        byte[] contents;
        try (SeekableByteChannel channel = Files.newByteChannel(path, options);
                InputStream stream = Channels.newInputStream(channel)) {
            if (channel.size() > MAX_RULE_BYTES) {
                throw new IOException("framework rule file exceeds 1 MiB");
            }
            contents = stream.readNBytes(MAX_RULE_BYTES + 1);
        }
        if (contents.length > MAX_RULE_BYTES) {
            throw new IOException("framework rule file exceeds 1 MiB");
        }

        var decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        String text;
        try {
            text = decoder.decode(ByteBuffer.wrap(contents)).toString();
        }
        catch (CharacterCodingException error) {
            throw new IOException("framework rule file is not valid UTF-8", error);
        }
        List<String> rules = new ArrayList<>();
        for (String raw : text.lines().toList()) {
            String value = raw.split("#", 2)[0].trim();
            if (value.isEmpty()) {
                continue;
            }
            if (value.length() > MAX_RULE_CHARS) {
                throw new IOException("framework rule exceeds 256 characters");
            }
            rules.add(value);
            if (rules.size() > MAX_RULES) {
                throw new IOException("framework rule file exceeds 4096 entries");
            }
        }
        return rules;
    }

    static String normalizeAssembly(String value) {
        String normalized = value.trim();
        if (normalized.toLowerCase(Locale.ROOT).endsWith(".dll")) {
            normalized = normalized.substring(0, normalized.length() - 4);
        }
        return normalized.toLowerCase(Locale.ROOT);
    }

    public record FrameworkRule(String name, String source) {
    }

    public record AssemblyDecision(String assembly, boolean included, String reason) {
    }

    public record Selection(List<Il2CppClassCatalog.ClassEntry> classes,
            Map<String, AssemblyDecision> assemblies) {
    }
}
