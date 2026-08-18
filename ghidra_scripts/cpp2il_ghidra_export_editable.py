# @category Extraction
# @menupath Tools.CPP2IL.Export Decompiled CPP2IL Classes (Editable)
# @toolbar
#
# Export Ghidra decompiler output using class names from a Cpp2IL DiffableCs directory.
# Usage: <DiffableCs> <output> [whitelist|blacklist|all] [framework-ignore|-]
#        [--noreturn-seeds <file>] [--decompile-jobs <0..12>]

import os
import re
import time
import traceback

from ghidra.app.decompiler import DecompInterface
from ghidra.app.plugin.core.analysis import AutoAnalysisManager
from ghidra.util.task import ConsoleTaskMonitor
from java.util import ArrayList
from turboheader.il2cpp import (
    Il2CppDecompilerService,
    Il2CppExportedHelperAnalyzer,
    Il2CppNoreturnAnalyzer,
    Il2CppRuntimeMetadataAnalyzer,
)


# Configuration

# Available values:
#
#   "whitelist"
#   "blacklist"
#   "all"
#
# A command-line/headless script argument overrides this value.
ASSEMBLY_SELECTION_MODE = "blacklist"


# Used only in whitelist mode.
#
# Use ["*"] or [] for every assembly.
SELECTED_ASSEMBLIES = [
    "Assembly-CSharp",
    "Assembly-CSharp-firstpass",
]


# Pick individual classes.
#
# Empty means all classes in the assemblies selected by the current mode.
#
# Accepted forms:
#
#   "AudioManager"
#   "AFMiniJSON/ba"
#   "AFMiniJSON.ba"
#   "AFMiniJSON/ba.cs"
SELECTED_CLASSES = []


# Optional explicit ignore-list path.
#
# Empty means try to locate framework_ignore.txt in:
#
#   1. the current working directory;
#   2. the DiffableCs directory;
#   3. the parent directory of DiffableCs.
#
# A fourth headless script argument overrides this value.
FRAMEWORK_IGNORE_FILE = ""


# Ghidra decompiler timeout per function.
DECOMPILE_TIMEOUT_SECS = 60


ASSEMBLY_COMMENT_PREFIX = "TurboHeader assembly: "


# Run the enabled Ghidra analyzers after disassembling/recreating each function.
#
# This helps decompilation, but it can make a whole-app export considerably
# slower. The analyzer configuration itself is now performed only once.
ANALYZE_CHANGES_PER_FUNCTION = True

# Optional ELF-virtual addresses proven non-returning by il2cppAOTopsy's
# conservative raw AArch64 CFG pass. When supplied, this replaces Ghidra's
# expensive whole-program heuristic discovery analyzer.
NORETURN_SEEDS_FILE = ""


# Zero preserves the existing interleaved sequential exporter. One enables the
# staged Java decompiler service serially. Two through eight are validated
# fixed-lane topologies. Nine through twelve remain explicit experimental
# worker-count choices; higher worker counts remain gated.
DECOMPILE_JOBS = 0


# Create a .cpp file even when no functions matched that class.
WRITE_EMPTY_CLASS_FILES = True


# Try matching functions by simple class name when namespace/path matching
# does not succeed.
ALLOW_SIMPLE_NAME_FALLBACK = True


# When a simple class name matches several classes:
#
# False:
#     log the ambiguity and skip the function;
#
# True:
#     duplicate the function into every matching class file.
DUPLICATE_AMBIGUOUS_SIMPLE_MATCHES = False


# Optional generated/support-file filters.
SKIP_GENERATED_ASSEMBLY = False
SKIP_PRIVATE_IMPLEMENTATION_DETAILS = False
SKIP_MODULE_FILES = False


# Only print/write selection logs without decompiling function bodies.
DRY_RUN = False


# Framework filters

# These rules are always active in blacklist mode.
#
# Matching is case-insensitive and boundary-aware:
#
#   Firebase matches:
#       Firebase
#       Firebase.App
#       Firebase-Plugin
#
#   Firebase does not match:
#       FirebaseEvil
#
# External framework_ignore.txt entries are unioned with these defaults.

BUILTIN_FRAMEWORK_IGNORES = (
    # Engine glue
    "__Generated",

    # Analytics / attribution / crash
    "AppsFlyer",
    "Adjust",
    "AdjustSdk",
    "Facebook",
    "Firebase",
    "GameAnalytics",
    "Singular",
    "Tenjin",
    "Kochava",
    "Branch",
    "Amplitude",
    "Flurry",
    "Mixpanel",
    "Segment",
    "Bugsnag",
    "Sentry",
    "ByteBrew",

    # Ad networks / mediation
    "GoogleMobileAds",
    "AudienceNetwork",
    "UnityAds",
    "IronSource",
    "AppLovin",
    "MoPub",
    "Chartboost",
    "Vungle",
    "AdColony",
    "Mintegral",
    "Pangle",
    "Fyber",
    "Yodo1",
    "Tapjoy",
    "Unity.Advertisement",

    # Networking / backend / serialization
    "BestHTTP",
    "WebSocketSharp",
    "Google",
    "protobuf",
    "Photon",
    "PlayFab",
    "Nakama",
    "Mirror",
    "Newtonsoft",
    "LitJson",
    "SimpleJSON",
    "Sirenix",
    "OdinSerializer",
    "Odin",
    "MessagePack",
    "ZString",

    # Tweening / animation / audio / rendering
    "DOTween",
    "DOTweenPro",
    "LeanTween",
    "PrimeTween",
    "Spine",
    "Animancer",
    "Cinemachine",
    "MoreMountains",
    "FMOD",
    "Wwise",
    "ToonyColorsPro",
    "ToonyColorsPro2",

    # Async / DI / reactive / input
    "UniTask",
    "Cysharp",
    "UniRx",
    "R3",
    "Zenject",
    "Extenject",
    "VContainer",
    "Rewired",
    "InControl",

    # UI / debug / webview / utilities
    "UltEvents",
    "NaughtyAttributes",
    "SRDebugger",
    "StompyRobot",
    "ConsolePro",
    "ConsoleProDebug",
    "ConsoleProRemote",
    "IngameDebugConsole",
    "UniWebView",
    "Michsky",
    "Coffee",
    "MPUIKit",
    "TMPro",

    # Scripting / obfuscation / interop
    "ILRuntime",
    "Lua",
    "XLua",
    "OPS",
    "GUPS",
    "Beebyte",
    "Obfuz",
    "Mono",
)


# Name-based automatic filters that do not require framework_ignore.txt.
#
# This exporter sees the DiffableCs assembly directory names. It does not
# reliably have strong-name or AssemblyCompany metadata, so those two checks
# cannot safely be implemented here without an additional metadata source.
AUTO_FRAMEWORK_IGNORES = (
    "Unity",
    "UnityEngine",
    "mscorlib",
    "netstandard",
    "System",
    "Microsoft",
)


# Analysis

def run_non_returning_analysis():
    print(
        "Configuring auto-analysis to only run "
        "Non-Returning function analyzers..."
    )

    options = currentProgram.getOptions("Analyzers")

    for option_name in options.getOptionNames():
        if str(options.getType(option_name)) != "BOOLEAN_TYPE":
            continue

        options.setBoolean(
            option_name,
            "Non-Returning" in option_name,
        )

    print("Triggering auto-analysis...")
    analyzeChanges(currentProgram)
    print("Auto-analysis complete.")


def configure_cpp2il_optimized_analysis():
    print("Configuring optimized IL2CPP analysis...")

    options = currentProgram.getOptions("Analyzers")

    boolean_names = set()
    integer_names = set()

    for option_name in options.getOptionNames():
        option_name = str(option_name)

        option_type = str(options.getType(option_name))

        if option_type == "BOOLEAN_TYPE":
            boolean_names.add(option_name)
            options.setBoolean(option_name, False)

        elif option_type == "INT_TYPE":
            integer_names.add(option_name)

    enabled_analyzers = {
        "AARCH64 ELF PLT Thunks",
        "ARM Constant Reference Analyzer",
        "Subroutine References",
        "Shared Return Calls",
        "Reference",
        "ELF Scalar Operand References",
        "External Entry References",
        "Call-Fixup Installer",
        "Non-Returning Functions - Known",
    }

    # Local raw-word discovery is AArch64-only. Preserve Ghidra's previous
    # architecture-independent fallback for other targets when no external
    # proven seed file was supplied.
    if not use_java_noreturn_analysis(NORETURN_SEEDS_FILE):
        enabled_analyzers.add("Non-Returning Functions - Discovered")

    # Enable only the analyzer root checkboxes.
    for analyzer_name in sorted(enabled_analyzers):
        if analyzer_name in boolean_names:
            options.setBoolean(analyzer_name, True)
            print("  enabled: {}".format(analyzer_name))
        else:
            print("  unavailable: {}".format(analyzer_name))

    suboptions = {
        # Important for the thunk_FUN_* differences.
        "Subroutine References.Create Thunks Early": True,

        # Useful and conservative for normal compiler output.
        "Shared Return Calls.Assume Contiguous Functions Only": True,

        # Avoid interpreting arbitrary conditional branches as tail calls.
        "Shared Return Calls.Allow Conditional Jumps": False,

        # Create call/function references, but not global tables.
        "Reference.Subroutine References": True,
        "Reference.Create Address Tables": False,
        "Reference.Switch Table References": False,

        # Use ELF relocation information.
        "ELF Scalar Operand References.Relocation Table Guide": True,

        # Used when exception analysis has already run outside the fast profile.
        "GCC Exception Handlers.Create Try Catch Comments": True,

        # Repair damage caused by previously unidentified non-return calls.
        "Non-Returning Functions - Discovered.Repair Flow Damage": True,

        # Bookmarks are diagnostic UI state and add no decompilation value.
        "Non-Returning Functions - Discovered.Create Analysis Bookmarks": False,
        "Non-Returning Functions - Known.Create Analysis Bookmarks": False,
    }

    for option_name, enabled in suboptions.items():
        if option_name in boolean_names:
            options.setBoolean(option_name, enabled)

    integer_suboptions = {
        # Require repeated call-site evidence before discovery marks a function
        # non-returning. Pin the value so a Ghidra default change cannot alter
        # IL2CPP function boundaries silently.
        "Non-Returning Functions - Discovered.Function Non-return Threshold": 3,
    }

    for option_name, value in integer_suboptions.items():
        if option_name in integer_names:
            options.setInt(option_name, value)

    # AnalysisScheduler caches analyzer root state. Refresh it after changing
    # program options so per-function analyzeChanges() uses this profile.
    AutoAnalysisManager.getAnalysisManager(
        currentProgram
    ).initializeOptions()


def run_optimized_global_analysis(task_monitor):
    manager = AutoAnalysisManager.getAnalysisManager(
        currentProgram
    )

    scheduled = []

    for analyzer_name in (
        "AARCH64 ELF PLT Thunks",
    ):
        analyzer = manager.getAnalyzer(
            analyzer_name
        )

        if analyzer is None:
            continue

        if not analyzer.canAnalyze(
                currentProgram):
            continue

        manager.scheduleOneTimeAnalysis(
            analyzer,
            currentProgram.getMemory(),
        )

        scheduled.append(
            analyzer_name
        )

    if not scheduled:
        return

    print(
        "Running one-time global analysis: %s"
        % ", ".join(scheduled)
    )

    manager.startAnalysis(
        task_monitor,
        True,
    )


def use_java_noreturn_analysis(path):
    if path:
        return True
    try:
        processor = str(
            currentProgram.getLanguage().getProcessor()
        )
        return processor.upper() == "AARCH64"
    except Exception:
        # Ghidra always exposes a language. Keep the conservative custom path
        # in test/minimal environments that do not provide that API.
        return True


def run_il2cpp_noreturn_analysis(path, task_monitor):
    """Delegate seed loading or local discovery and all mutations to Java."""
    if not use_java_noreturn_analysis(path):
        print(
            "TurboHeader noreturn: source=ghidra-builtin "
            "(local discovery supports AARCH64 only)"
        )
        return
    resolved = expand_path(path) if path else ""
    stats = Il2CppNoreturnAnalyzer.analyze(
        currentProgram,
        resolved,
        task_monitor,
    )
    print(
        "TurboHeader noreturn: source=%s, proven=%d, marked=%d, "
        "helpers=%d, renamed=%d, already-named=%d, preserved=%d, "
        "CALL_RETURN=%d, repaired=%d, discovery=%.3fs, "
        "application=%.3fs, total=%.3fs"
        % (
            stats.source(),
            stats.provenAddresses(),
            stats.markedFunctions(),
            stats.provenHelpers(),
            stats.helpersRenamed(),
            stats.helperNamesAlreadyApplied(),
            stats.helperNamesPreserved(),
            stats.callOverrides(),
            stats.repairedCallers(),
            stats.discoverySeconds(),
            stats.applicationSeconds(),
            stats.totalSeconds(),
        )
    )
    if stats.source() == "ghidra-local":
        print(
            "TurboHeader noreturn fallback: managed instructions=%d, "
            "helper instructions=%d, helper summaries=%d"
            % (
                stats.managedInstructions(),
                stats.helperInstructions(),
                stats.helperSummaries(),
            )
        )


def run_il2cpp_runtime_metadata_analysis(task_monitor):
    stats = Il2CppRuntimeMetadataAnalyzer.analyze(
        currentProgram,
        task_monitor,
    )
    print(
        "TurboHeader runtime metadata: probes=%d/%d, slots=%d, "
        "helper=%s, outcome=%s, total=%.3fs"
        % (
            stats.completedProbes(),
            stats.probes(),
            stats.metadataSlots(),
            stats.helperAddress() or "none",
            stats.outcome(),
            stats.elapsedSeconds(),
        )
    )


def run_il2cpp_exported_helper_analysis(functions, task_monitor):
    stats = Il2CppExportedHelperAnalyzer(
        currentProgram,
        functions,
        task_monitor,
    ).analyze()
    print(
        "TurboHeader helpers: functions=%d, exports=%d, candidates=%d, "
        "proven=%d, ambiguous=%d, renamed=%d, already-named=%d, "
        "preserved=%d, typed=%d, total=%.3fs"
        % (
            stats.selectedFunctions(),
            stats.resolvedExports(),
            stats.compilerCandidates(),
            stats.provenHelpers(),
            stats.ambiguousCandidates(),
            stats.renamed(),
            stats.alreadyNamed(),
            stats.preserved(),
            stats.typed(),
            stats.elapsedSeconds(),
        )
    )


# Data classes

class ClassMeta(object):

    def __init__(self, assembly, rel_cs_path):
        self.assembly = assembly

        self.rel_cs_path = rel_cs_path.replace(
            "\\",
            "/",
        )

        self.file_name = os.path.basename(
            self.rel_cs_path
        )

        self.class_name = os.path.splitext(
            self.file_name
        )[0]

        self.dir_rel = os.path.dirname(
            self.rel_cs_path
        ).replace(
            "\\",
            "/",
        )

        if self.dir_rel:
            self.namespace_name = self.dir_rel.replace(
                "/",
                ".",
            )
        else:
            self.namespace_name = ""

    def output_rel_cpp_path(self):
        root, _extension = os.path.splitext(
            self.rel_cs_path
        )

        return sanitize_rel_path(
            root + ".cpp"
        )

    def display_name(self):
        if self.dir_rel:
            return (
                self.assembly
                + "/"
                + self.dir_rel
                + "/"
                + self.class_name
            )

        return (
            self.assembly
            + "/"
            + self.class_name
        )

    def list_label(self):
        return os.path.splitext(
            self.rel_cs_path
        )[0].replace(
            "\\",
            "/",
        )

    def selection_keys(self):
        keys = set()

        rel_no_extension = os.path.splitext(
            self.rel_cs_path
        )[0].replace(
            "\\",
            "/",
        )

        keys.add(
            self.class_name.lower()
        )

        keys.add(
            rel_no_extension.lower()
        )

        keys.add(
            rel_no_extension.replace(
                "/",
                ".",
            ).lower()
        )

        keys.add(
            self.rel_cs_path.lower()
        )

        if self.namespace_name:
            keys.add(
                (
                    self.namespace_name
                    + "."
                    + self.class_name
                ).lower()
            )

        return keys

    def candidate_names(self):
        names = set()

        rel_no_extension = os.path.splitext(
            self.rel_cs_path
        )[0].replace(
            "\\",
            "/",
        )

        names.add(
            self.class_name
        )

        if rel_no_extension:
            names.add(
                rel_no_extension
            )

            names.add(
                rel_no_extension.replace(
                    "/",
                    ".",
                )
            )

            names.add(
                rel_no_extension.replace(
                    "/",
                    "_",
                )
            )

        if self.namespace_name:
            names.add(
                self.namespace_name
                + "."
                + self.class_name
            )

            names.add(
                self.namespace_name.replace(
                    ".",
                    "_",
                )
                + "_"
                + self.class_name
            )

        return list(names)


class CandidateHit(object):

    def __init__(
            self,
            meta,
            kind,
            token_count):

        self.meta = meta
        self.kind = kind
        self.token_count = token_count


class ExportStats(object):

    def __init__(self):
        self.functions_total = 0
        self.functions_matched = 0
        self.functions_failed = 0
        self.decompiler_restarts = 0
        self.functions_recovered = 0
        self.assembly_ambiguities_resolved = 0
        self.assembly_mismatches_skipped = 0

        self.classes_total = 0
        self.classes_written = 0

        self.ambiguous = []

        self.class_scan_seconds = 0.0
        self.analysis_seconds = 0.0
        self.function_preparation_seconds = 0.0
        self.decompilation_seconds = 0.0
        self.output_writing_seconds = 0.0
        self.total_export_seconds = 0.0


class TimedOutput(object):

    def __init__(self, output_file, stats):
        self.output_file = output_file
        self.stats = stats

    def write(self, value):
        started = time.monotonic()
        try:
            return self.output_file.write(value)
        finally:
            self.stats.output_writing_seconds += (
                time.monotonic() - started
            )


# Paths

def expand_path(path):
    return os.path.abspath(
        os.path.expandvars(
            os.path.expanduser(
                str(path)
            )
        )
    )


def sanitize_filename(name):
    return re.sub(
        r'[<>:"\\|?*\x00-\x1f]',
        "_",
        str(name),
    )


def sanitize_rel_path(rel_path):
    parts = []

    for part in rel_path.replace(
            "\\",
            "/").split("/"):

        if not part or part == ".":
            continue

        if part == "..":
            parts.append("__")
        else:
            parts.append(
                sanitize_filename(part)
            )

    return "/".join(parts)


def ensure_dir(path):
    if path and not os.path.isdir(path):
        os.makedirs(path)


# Framework filtering

def normalize_assembly_name(name):
    value = str(name).strip()

    if value.lower().endswith(".dll"):
        value = value[:-4]

    return value.lower()


def assembly_matches_ignore_rule(
        assembly_name,
        rule):
    """
    Match an exact assembly or a '.'/'-' separated child.

    Examples:

        Firebase       -> Firebase
        Firebase       -> Firebase.App
        Firebase       -> Firebase-Plugin
        Firebase       !-> FirebaseEvil
        Spine          -> spine-unity
    """
    assembly_normalized = normalize_assembly_name(
        assembly_name
    )

    rule_normalized = normalize_assembly_name(
        rule
    )

    if not rule_normalized:
        return False

    return (
        assembly_normalized == rule_normalized
        or assembly_normalized.startswith(
            rule_normalized + "."
        )
        or assembly_normalized.startswith(
            rule_normalized + "-"
        )
    )


def parse_framework_ignore_file(path):
    entries = []

    with open(path, "r") as ignore_file:
        for raw_line in ignore_file:
            # Permit full-line and inline comments.
            line = raw_line.split(
                "#",
                1,
            )[0].strip()

            if line:
                entries.append(line)

    return entries


def discover_framework_ignore_file(
        diffable_cs_dir,
        configured_path):
    candidates = []

    if configured_path:
        candidates.append(
            expand_path(configured_path)
        )

    candidates.extend([
        os.path.join(
            os.getcwd(),
            "framework_ignore.txt",
        ),
        os.path.join(
            diffable_cs_dir,
            "framework_ignore.txt",
        ),
        os.path.join(
            os.path.dirname(diffable_cs_dir),
            "framework_ignore.txt",
        ),
    ])

    seen = set()

    for candidate in candidates:
        candidate = os.path.abspath(
            candidate
        )

        if candidate in seen:
            continue

        seen.add(candidate)

        if os.path.isfile(candidate):
            return candidate

    if configured_path:
        raise IOError(
            "Configured framework ignore file "
            "does not exist: "
            + expand_path(configured_path)
        )

    return None


def build_framework_ignore_rules(
        diffable_cs_dir,
        configured_path):
    """
    Return:

        rules:
            list of (rule, source) pairs

        ignore_file:
            resolved framework_ignore.txt path, or None
    """
    rules = []
    seen = set()

    def add_rules(entries, source):
        for entry in entries:
            normalized = normalize_assembly_name(
                entry
            )

            if not normalized:
                continue

            if normalized in seen:
                continue

            seen.add(normalized)

            rules.append(
                (
                    str(entry).strip(),
                    source,
                )
            )

    add_rules(
        BUILTIN_FRAMEWORK_IGNORES,
        "built-in",
    )

    add_rules(
        AUTO_FRAMEWORK_IGNORES,
        "automatic",
    )

    ignore_file = discover_framework_ignore_file(
        diffable_cs_dir,
        configured_path,
    )

    if ignore_file:
        add_rules(
            parse_framework_ignore_file(
                ignore_file
            ),
            "file: " + ignore_file,
        )

    return rules, ignore_file


def find_matching_framework_rule(
        assembly_name,
        rules):
    matches = []

    for rule, source in rules:
        if assembly_matches_ignore_rule(
                assembly_name,
                rule):

            matches.append(
                (
                    rule,
                    source,
                )
            )

    if not matches:
        return None

    # Prefer the longest/more-specific matching rule for logging.
    matches.sort(
        key=lambda item: len(
            normalize_assembly_name(
                item[0]
            )
        ),
        reverse=True,
    )

    return matches[0]


def normalize_assembly_selection_mode(mode):
    value = str(
        mode or ""
    ).strip().lower()

    aliases = {
        "white": "whitelist",
        "allowlist": "whitelist",
        "selected": "whitelist",

        "black": "blacklist",
        "denylist": "blacklist",
        "app": "blacklist",
        "all-except-blacklist": "blacklist",

        "*": "all",
        "everything": "all",
        "all-assemblies": "all",
    }

    value = aliases.get(
        value,
        value,
    )

    if value not in (
            "whitelist",
            "blacklist",
            "all"):

        raise ValueError(
            "Unknown assembly-selection mode %r. "
            "Expected whitelist, blacklist or all."
            % mode
        )

    return value


# Cpp2IL class discovery

def should_skip(
        assembly,
        rel_cs_path):
    base_name = os.path.basename(
        rel_cs_path
    )

    if (
        SKIP_GENERATED_ASSEMBLY
        and assembly.lower() == "__generated"
    ):
        return True

    if (
        SKIP_PRIVATE_IMPLEMENTATION_DETAILS
        and base_name
        == "_PrivateImplementationDetails_.cs"
    ):
        return True

    if (
        SKIP_MODULE_FILES
        and base_name == "_Module_.cs"
    ):
        return True

    return False


def load_classes_from_cpp2il_dir(
        diffable_cs_dir):
    diffable_cs_dir = expand_path(
        diffable_cs_dir
    )

    if not os.path.isdir(
            diffable_cs_dir):

        raise IOError(
            "Expected a real cpp2il DiffableCs "
            "directory, not a tree.txt file: "
            + diffable_cs_dir
        )

    classes = []

    assemblies = sorted(
        os.listdir(diffable_cs_dir)
    )

    for assembly in assemblies:
        assembly_path = os.path.join(
            diffable_cs_dir,
            assembly,
        )

        if not os.path.isdir(
                assembly_path):
            continue

        for root, directories, files in os.walk(
                assembly_path):

            directories.sort()

            for name in sorted(files):
                if not name.lower().endswith(
                        ".cs"):
                    continue

                absolute_path = os.path.join(
                    root,
                    name,
                )

                relative_path = os.path.relpath(
                    absolute_path,
                    assembly_path,
                ).replace(
                    "\\",
                    "/",
                )

                if should_skip(
                        assembly,
                        relative_path):
                    continue

                classes.append(
                    ClassMeta(
                        assembly,
                        relative_path,
                    )
                )

    return classes


def select_classes(
        classes,
        selected_assemblies,
        selected_classes,
        selection_mode,
        framework_rules):

    selection_mode = (
        normalize_assembly_selection_mode(
            selection_mode
        )
    )

    selected_assemblies = (
        selected_assemblies or ["*"]
    )

    selected_classes = (
        selected_classes or []
    )

    whitelist_all = (
        "*" in selected_assemblies
        or "ALL" in selected_assemblies
    )

    whitelist_set = set([
        normalize_assembly_name(value)
        for value in selected_assemblies
    ])

    class_set = set()

    for selected_class in selected_classes:
        value = str(
            selected_class
        ).replace(
            "\\",
            "/",
        ).strip().lower()

        if value.endswith(".cpp"):
            value = (
                value[:-4]
                + ".cs"
            )

        if value.endswith(".cs"):
            class_set.add(value)
            class_set.add(
                value[:-3]
            )

            class_set.add(
                value[:-3].replace(
                    "/",
                    ".",
                )
            )

        else:
            class_set.add(value)

            class_set.add(
                value.replace(
                    "/",
                    ".",
                )
            )

    selected = []
    assembly_decisions = {}

    for meta in classes:
        assembly_key = normalize_assembly_name(
            meta.assembly
        )

        if assembly_key not in assembly_decisions:
            include_assembly = True
            reason = "included"

            if selection_mode == "whitelist":
                include_assembly = (
                    whitelist_all
                    or assembly_key in whitelist_set
                )

                if include_assembly:
                    reason = "selected by whitelist"
                else:
                    reason = (
                        "not present in "
                        "SELECTED_ASSEMBLIES"
                    )

            elif selection_mode == "blacklist":
                matched_rule = (
                    find_matching_framework_rule(
                        meta.assembly,
                        framework_rules,
                    )
                )

                if matched_rule is not None:
                    rule, source = matched_rule

                    include_assembly = False

                    reason = (
                        "matched %s rule %r"
                        % (
                            source,
                            rule,
                        )
                    )

                else:
                    reason = "not blacklisted"

            elif selection_mode == "all":
                reason = "all-assemblies mode"

            assembly_decisions[assembly_key] = (
                meta.assembly,
                include_assembly,
                reason,
            )

        (
            _assembly_name,
            include_assembly,
            _reason,
        ) = assembly_decisions[assembly_key]

        if not include_assembly:
            continue

        if class_set:
            class_matched = False

            for key in meta.selection_keys():
                if key in class_set:
                    class_matched = True
                    break

            if not class_matched:
                continue

        selected.append(meta)

    return selected, assembly_decisions


# Function and class matching

def normalize_symbol_name(name):
    """
    Convert punctuation and namespace separators into token boundaries.

    This prevents a one-letter class such as 'a' from matching every symbol
    that merely contains the letter 'a'.
    """
    value = str(name)

    output = []
    previous_was_underscore = False

    for character in value:
        if character.isalnum():
            output.append(
                character.lower()
            )

            previous_was_underscore = False

        else:
            if not previous_was_underscore:
                output.append("_")
                previous_was_underscore = True

    normalized = "".join(
        output
    ).strip("_")

    while "__" in normalized:
        normalized = normalized.replace(
            "__",
            "_",
        )

    return normalized


def class_candidate_kind(
        raw_name,
        meta):
    normalized_base = normalize_symbol_name(
        meta.class_name
    )

    normalized_raw = normalize_symbol_name(
        raw_name
    )

    if normalized_raw == normalized_base:
        return "simple"

    return "full"


def build_candidate_index(classes):
    index = {}
    maximum_tokens = 1

    for meta in classes:
        for raw_name in meta.candidate_names():
            normalized = normalize_symbol_name(
                raw_name
            )

            if not normalized:
                continue

            token_count = len(
                normalized.split("_")
            )

            if token_count > maximum_tokens:
                maximum_tokens = token_count

            kind = class_candidate_kind(
                raw_name,
                meta,
            )

            if (
                not ALLOW_SIMPLE_NAME_FALLBACK
                and kind == "simple"
            ):
                continue

            index.setdefault(
                normalized,
                [],
            )

            duplicate = False

            for hit in index[normalized]:
                if (
                    hit.meta is meta
                    and hit.kind == kind
                ):
                    duplicate = True
                    break

            if not duplicate:
                index[normalized].append(
                    CandidateHit(
                        meta,
                        kind,
                        token_count,
                    )
                )

    return index, maximum_tokens


def get_function_full_name(function):
    try:
        symbol = function.getSymbol()

        if symbol is not None:
            return str(
                symbol.getName(True)
            )

    except Exception:
        pass

    return str(
        function.getName()
    )


def get_function_assembly(function):
    try:
        comment = function.getComment()
    except Exception:
        return None

    if not comment:
        return None

    for line in str(comment).splitlines():
        if line.startswith(ASSEMBLY_COMMENT_PREFIX):
            assembly = line[len(ASSEMBLY_COMMENT_PREFIX):].strip()
            if assembly:
                return assembly

    return None


def find_matching_classes(
        function,
        candidate_index,
        maximum_tokens,
        stats):
    names_to_try = [
        get_function_full_name(
            function
        )
    ]

    try:
        simple_name = str(
            function.getName()
        )

        if simple_name not in names_to_try:
            names_to_try.append(
                simple_name
            )

    except Exception:
        pass

    best_hits = None
    best_key = None
    best_token_count = -1

    for raw_name in names_to_try:
        normalized = normalize_symbol_name(
            raw_name
        )

        if not normalized:
            continue

        tokens = normalized.split("_")

        limit = min(
            len(tokens),
            maximum_tokens,
        )

        # Longest prefix wins:
        #
        #   Namespace_Class
        #
        # takes priority over:
        #
        #   Class
        for token_count in range(
                limit,
                0,
                -1):

            key = "_".join(
                tokens[:token_count]
            )

            hits = candidate_index.get(
                key
            )

            if (
                hits
                and token_count
                > best_token_count
            ):
                best_hits = hits
                best_key = key
                best_token_count = token_count
                break

    if not best_hits:
        return []

    unique_hits = []
    seen = set()

    for hit in best_hits:
        display_name = hit.meta.display_name()

        if display_name not in seen:
            unique_hits.append(hit)
            seen.add(display_name)

    function_assembly = get_function_assembly(function)

    if function_assembly:
        assembly_key = normalize_assembly_name(function_assembly)
        matching_hits = [
            hit
            for hit in unique_hits
            if normalize_assembly_name(hit.meta.assembly) == assembly_key
        ]

        if not matching_hits:
            stats.assembly_mismatches_skipped += 1
            return []

        if len(unique_hits) > 1 and len(matching_hits) == 1:
            stats.assembly_ambiguities_resolved += 1

        unique_hits = matching_hits

    if (
        len(unique_hits) > 1
        and not DUPLICATE_AMBIGUOUS_SIMPLE_MATCHES
    ):
        stats.ambiguous.append(
            (
                str(function.getName()),
                best_key,
                [
                    hit.meta.display_name()
                    for hit in unique_hits
                ],
            )
        )

        return []

    return [
        hit.meta
        for hit in unique_hits
    ]


# Log writing

def write_log_files(
        output_root,
        stats,
        no_match_classes,
        assembly_mode,
        framework_ignore_file,
        assembly_decisions):
    ensure_dir(output_root)

    included_assemblies = [
        item
        for item in assembly_decisions.values()
        if item[1]
    ]

    skipped_assemblies = [
        item
        for item in assembly_decisions.values()
        if not item[1]
    ]

    summary_path = os.path.join(
        output_root,
        "_export_summary.txt",
    )

    with open(summary_path, "w") as summary_file:
        summary_file.write(
            "Ghidra cpp2il decompilation export summary\n"
        )

        summary_file.write(
            "Program: %s\n"
            % str(currentProgram.getName())
        )

        summary_file.write(
            "Class source: real cpp2il DiffableCs "
            "directory; class names from .cs filenames\n"
        )

        summary_file.write(
            "Assembly selection mode: %s\n"
            % assembly_mode
        )

        summary_file.write(
            "Framework ignore file: %s\n"
            % (
                framework_ignore_file
                or "<built-in defaults only>"
            )
        )

        summary_file.write(
            "Assemblies included: %d\n"
            % len(included_assemblies)
        )

        summary_file.write(
            "Assemblies skipped: %d\n"
            % len(skipped_assemblies)
        )

        summary_file.write(
            "Classes selected: %d\n"
            % stats.classes_total
        )

        summary_file.write(
            "Class files written: %d\n"
            % stats.classes_written
        )

        summary_file.write(
            "Functions scanned: %d\n"
            % stats.functions_total
        )

        summary_file.write(
            "Functions matched/exported: %d\n"
            % stats.functions_matched
        )

        summary_file.write(
            "Functions failed to decompile: %d\n"
            % stats.functions_failed
        )

        summary_file.write(
            "Decompiler restarts: %d\n"
            % stats.decompiler_restarts
        )

        summary_file.write(
            "Functions recovered after restart: %d\n"
            % stats.functions_recovered
        )

        summary_file.write(
            "Ambiguous functions skipped: %d\n"
            % len(stats.ambiguous)
        )

        summary_file.write(
            "Assembly ambiguities resolved: %d\n"
            % stats.assembly_ambiguities_resolved
        )

        summary_file.write(
            "Assembly mismatches skipped: %d\n"
            % stats.assembly_mismatches_skipped
        )

        summary_file.write(
            "Classes with no matches: %d\n"
            % len(no_match_classes)
        )

        summary_file.write(
            "Decompile topology: %s\n"
            % (
                "legacy-sequential"
                if DECOMPILE_JOBS == 0
                else "staged-java-jobs-%d"
                % DECOMPILE_JOBS
            )
        )

        summary_file.write(
            "Timing class scan seconds: %.6f\n"
            % stats.class_scan_seconds
        )

        summary_file.write(
            "Timing analysis seconds: %.6f\n"
            % stats.analysis_seconds
        )

        summary_file.write(
            "Timing function preparation seconds: %.6f\n"
            % stats.function_preparation_seconds
        )

        summary_file.write(
            "Timing decompilation seconds: %.6f\n"
            % stats.decompilation_seconds
        )

        summary_file.write(
            "Timing output writes seconds: %.6f\n"
            % stats.output_writing_seconds
        )

        summary_file.write(
            "Timing total export seconds: %.6f\n"
            % stats.total_export_seconds
        )

        summary_file.write(
            "\nMatching note: class names are matched at "
            "token boundaries, so one-letter classes only "
            "match symbols whose first token/path component "
            "is that exact letter.\n"
        )

    assembly_log_path = os.path.join(
        output_root,
        "_assembly_filter.txt",
    )

    with open(
            assembly_log_path,
            "w") as assembly_log:

        assembly_log.write(
            "Assembly selection mode: %s\n"
            % assembly_mode
        )

        assembly_log.write(
            "Framework ignore file: %s\n\n"
            % (
                framework_ignore_file
                or "<built-in defaults only>"
            )
        )

        decisions = sorted(
            assembly_decisions.values(),
            key=lambda item: item[0].lower(),
        )

        for (
            assembly_name,
            included,
            reason,
        ) in decisions:

            if included:
                status = "INCLUDE"
            else:
                status = "SKIP"

            assembly_log.write(
                "[%s] %s -- %s\n"
                % (
                    status,
                    assembly_name,
                    reason,
                )
            )

    if stats.ambiguous:
        ambiguous_path = os.path.join(
            output_root,
            "_ambiguous_matches.txt",
        )

        with open(
                ambiguous_path,
                "w") as ambiguous_file:

            for (
                function_name,
                key,
                names,
            ) in stats.ambiguous:

                ambiguous_file.write(
                    "Function: %s\n"
                    % function_name
                )

                ambiguous_file.write(
                    "Matched key: %s\n"
                    % key
                )

                ambiguous_file.write(
                    "Candidate classes:\n"
                )

                for name in names:
                    ambiguous_file.write(
                        "  - %s\n"
                        % name
                    )

                ambiguous_file.write("\n")

    if no_match_classes:
        no_match_path = os.path.join(
            output_root,
            "_classes_with_no_matches.txt",
        )

        with open(
                no_match_path,
                "w") as no_match_file:

            for meta in no_match_classes:
                no_match_file.write(
                    meta.display_name()
                    + "\n"
                )


# Optional recursive call-graph support

def get_recursive_addresses(
        start_function,
        address_set,
        visited_functions):
    if start_function in visited_functions:
        return

    visited_functions.add(
        start_function
    )

    address_set.add(
        start_function.getBody()
    )

    called_functions = (
        start_function.getCalledFunctions(
            None
        )
    )

    for called_function in called_functions:
        get_recursive_addresses(
            called_function,
            address_set,
            visited_functions,
        )


# Decompilation export

def open_decompiler():
    decompiler = DecompInterface()
    if not decompiler.openProgram(currentProgram):
        decompiler.dispose()
        raise RuntimeError("Ghidra decompiler did not open the current program")
    return decompiler


def decompile_with_recovery(decompiler, function, task_monitor, stats):
    try:
        result = decompiler.decompileFunction(
            function,
            DECOMPILE_TIMEOUT_SECS,
            task_monitor,
        )
        if result.decompileCompleted():
            return decompiler, result
    except Exception:
        pass

    try:
        decompiler.dispose()
    except Exception:
        pass

    stats.decompiler_restarts += 1
    replacement = open_decompiler()

    try:
        result = replacement.decompileFunction(
            function,
            DECOMPILE_TIMEOUT_SECS,
            task_monitor,
        )
    except Exception:
        replacement.dispose()
        raise

    if result.decompileCompleted():
        stats.functions_recovered += 1

    return replacement, result


class PreparedFunction(object):

    def __init__(self, display_function):
        self.display_function = display_function
        self.decompile_function = display_function
        self.batch_index = None
        self.preparation_error = None
        self.result = None


def prepare_function_for_decompilation(
        function,
        stats):
    started = time.monotonic()
    try:
        entry_point = function.getEntryPoint()

        print(
            "Preparing decompilation at: %s (@ %s)"
            % (
                get_function_full_name(function),
                entry_point,
            )
        )

        disassemble(entry_point)

        recreated_function = createFunction(
            entry_point,
            None,
        )

        if recreated_function is not None:
            function = recreated_function

        print(
            "Created/Recreated function at %s"
            % entry_point
        )

        if ANALYZE_CHANGES_PER_FUNCTION:
            analyzeChanges(currentProgram)

        return function
    finally:
        stats.function_preparation_seconds += (
            time.monotonic() - started
        )


def prepare_staged_decompilation(
        classes,
        class_to_entries,
        task_monitor,
        stats):
    class_to_prepared = {}
    submitted = ArrayList()

    print(
        "Preparing all selected functions before "
        "the decompilation barrier..."
    )

    for meta in classes:
        prepared_for_class = []

        for function in class_to_entries.get(
                meta.display_name(),
                []):
            prepared = PreparedFunction(function)
            try:
                prepared.decompile_function = (
                    prepare_function_for_decompilation(
                        function,
                        stats,
                    )
                )
                prepared.batch_index = submitted.size()
                submitted.add(
                    prepared.decompile_function
                )
            except Exception as error:
                prepared.preparation_error = str(error)

            prepared_for_class.append(prepared)

        class_to_prepared[
            meta.display_name()
        ] = prepared_for_class

    print(
        "Preparation barrier reached; decompiling %d functions "
        "with Java jobs=%d."
        % (
            submitted.size(),
            DECOMPILE_JOBS,
        )
    )

    run_il2cpp_exported_helper_analysis(
        submitted,
        task_monitor,
    )

    decompile_started = time.monotonic()
    batch = Il2CppDecompilerService.decompileFunctions(
        currentProgram,
        submitted,
        DECOMPILE_JOBS,
        DECOMPILE_TIMEOUT_SECS,
        task_monitor,
    )
    stats.decompilation_seconds += (
        time.monotonic() - decompile_started
    )
    stats.decompiler_restarts += batch.getRetryCount()
    stats.functions_recovered += batch.getRecoveredCount()

    results = batch.getResults()
    for prepared_for_class in class_to_prepared.values():
        for prepared in prepared_for_class:
            if prepared.batch_index is not None:
                prepared.result = results.get(
                    prepared.batch_index
                )

    print(
        "Java decompilation complete: workers=%d, functions=%d, "
        "retries=%d, recovered=%d, first=%.3fs, retry=%.3fs, "
        "total=%.3fs"
        % (
            batch.getWorkerCount(),
            len(results),
            batch.getRetryCount(),
            batch.getRecoveredCount(),
            batch.getFirstPassSeconds(),
            batch.getRetryPassSeconds(),
            batch.getTotalSeconds(),
        )
    )

    return class_to_prepared

def export_classes_to_cpp(
        classes,
        output_root,
        assembly_mode,
        framework_ignore_file,
        assembly_decisions):
    export_started = time.monotonic()

    output_root = expand_path(
        output_root
    )

    ensure_dir(output_root)

    stats = ExportStats()
    stats.classes_total = len(classes)

    (
        candidate_index,
        maximum_tokens,
    ) = build_candidate_index(
        classes
    )

    class_to_entries = {}

    for meta in classes:
        class_to_entries[
            meta.display_name()
        ] = []

    print("Scanning Ghidra functions...")
    scan_started = time.monotonic()

    function_manager = (
        currentProgram.getFunctionManager()
    )

    for function in function_manager.getFunctions(
            True):

        if monitor.isCancelled():
            raise Exception(
                "Cancelled"
            )

        stats.functions_total += 1

        matched_classes = find_matching_classes(
            function,
            candidate_index,
            maximum_tokens,
            stats,
        )

        if not matched_classes:
            continue

        for meta in matched_classes:
            class_to_entries.setdefault(
                meta.display_name(),
                [],
            ).append(
                function
            )

    stats.class_scan_seconds = (
        time.monotonic() - scan_started
    )

    task_monitor = monitor

    try:
        if task_monitor is None:
            task_monitor = (
                ConsoleTaskMonitor()
            )

    except Exception:
        task_monitor = (
            ConsoleTaskMonitor()
        )

    if not DRY_RUN:
        analysis_started = time.monotonic()
        configure_cpp2il_optimized_analysis()
        run_optimized_global_analysis(
            task_monitor
        )
        run_il2cpp_noreturn_analysis(
            NORETURN_SEEDS_FILE,
            task_monitor,
        )
        run_il2cpp_runtime_metadata_analysis(
            task_monitor,
        )

        stats.analysis_seconds = (
            time.monotonic() - analysis_started
        )

    decompiler = None
    class_to_prepared = None

    if not DRY_RUN and DECOMPILE_JOBS == 0:
        print("Opening Ghidra decompiler...")
        decompile_started = time.monotonic()
        try:
            decompiler = open_decompiler()
        finally:
            stats.decompilation_seconds += (
                time.monotonic() - decompile_started
            )

    elif not DRY_RUN:
        class_to_prepared = prepare_staged_decompilation(
            classes,
            class_to_entries,
            task_monitor,
            stats,
        )

    no_match_classes = []

    try:
        for meta in classes:
            if monitor.isCancelled():
                raise Exception(
                    "Cancelled"
                )

            functions = class_to_entries.get(
                meta.display_name(),
                [],
            )

            if not functions:
                no_match_classes.append(
                    meta
                )

                if not WRITE_EMPTY_CLASS_FILES:
                    continue

            output_relative_path = (
                meta.output_rel_cpp_path()
            )

            output_path = os.path.join(
                output_root,
                sanitize_filename(
                    meta.assembly
                ),
                output_relative_path,
            )

            ensure_dir(
                os.path.dirname(
                    output_path
                )
            )

            stats.classes_written += 1

            print(
                "Writing %s (%d functions)"
                % (
                    output_path,
                    len(functions),
                )
            )

            if DRY_RUN:
                continue

            with open(
                    output_path,
                    "w") as raw_output_file:

                output_file = TimedOutput(
                    raw_output_file,
                    stats,
                )

                output_file.write(
                    "// Decompiled with Ghidra "
                    "from program: %s\n"
                    % str(
                        currentProgram.getName()
                    )
                )

                output_file.write(
                    "// cpp2il assembly: %s\n"
                    % meta.assembly
                )

                output_file.write(
                    "// cpp2il class file: %s\n"
                    % meta.rel_cs_path
                )

                output_file.write(
                    "// class name from filename: %s\n"
                    % meta.class_name
                )

                output_file.write(
                    "// namespace from folder path: %s\n\n"
                    % (
                        meta.namespace_name
                        or ""
                    )
                )

                if not functions:
                    output_file.write(
                        "// No Ghidra functions matched "
                        "this cpp2il class.\n"
                    )

                    continue

                prepared_for_class = (
                    class_to_prepared.get(
                        meta.display_name(),
                        [],
                    )
                    if class_to_prepared is not None
                    else None
                )

                for function_index, function in enumerate(functions):
                    output_file.write(
                        "\n"
                        "// --------------------------------"
                        "-------------------------------------\n"
                    )

                    output_file.write(
                        "// Function: %s\n"
                        % get_function_full_name(
                            function
                        )
                    )

                    output_file.write(
                        "// Address : %s\n"
                        % str(
                            function.getEntryPoint()
                        )
                    )

                    output_file.write(
                        "// --------------------------------"
                        "-------------------------------------\n"
                    )

                    try:
                        if prepared_for_class is not None:
                            prepared = prepared_for_class[
                                function_index
                            ]
                            if prepared.preparation_error is not None:
                                raise RuntimeError(
                                    prepared.preparation_error
                                )
                            result = prepared.result
                            if result is None:
                                raise RuntimeError(
                                    "No staged decompiler result"
                                )
                            completed = result.isCompleted()
                            c_code = result.getCCode()
                            error_message = (
                                result.getErrorMessage()
                            )
                        else:
                            function = (
                                prepare_function_for_decompilation(
                                    function,
                                    stats,
                                )
                            )
                            one_function = ArrayList()
                            one_function.add(function)
                            run_il2cpp_exported_helper_analysis(
                                one_function,
                                task_monitor,
                            )

                            decompile_started = time.monotonic()
                            try:
                                (
                                    decompiler,
                                    result,
                                ) = decompile_with_recovery(
                                    decompiler,
                                    function,
                                    task_monitor,
                                    stats,
                                )
                            finally:
                                stats.decompilation_seconds += (
                                    time.monotonic()
                                    - decompile_started
                                )

                            completed = result.decompileCompleted()
                            error_message = result.getErrorMessage()
                            c_code = None
                            if completed:
                                c_code = (
                                    result
                                    .getDecompiledFunction()
                                    .getC()
                                )

                        if completed:

                            output_file.write(
                                c_code
                            )

                            if not c_code.endswith("\n"):
                                output_file.write("\n")

                            stats.functions_matched += 1

                        else:
                            stats.functions_failed += 1

                            output_file.write(
                                "// Decompilation failed: %s\n"
                                % str(error_message)
                            )

                    except Exception as error:
                        stats.functions_failed += 1

                        output_file.write(
                            "// Decompilation exception: %s\n"
                            % str(error)
                        )

    finally:
        if decompiler is not None:
            try:
                decompiler.dispose()

            except Exception:
                pass

    stats.total_export_seconds = (
        time.monotonic() - export_started
    )

    print(
        "TurboHeader phase timing: scan=%.3fs, analysis=%.3fs, "
        "prepare=%.3fs, decompile=%.3fs, writes=%.3fs, total=%.3fs"
        % (
            stats.class_scan_seconds,
            stats.analysis_seconds,
            stats.function_preparation_seconds,
            stats.decompilation_seconds,
            stats.output_writing_seconds,
            stats.total_export_seconds,
        )
    )

    write_log_files(
        output_root,
        stats,
        no_match_classes,
        assembly_mode,
        framework_ignore_file,
        assembly_decisions,
    )

    print(
        "Done. Output: "
        + output_root
    )

    return stats

    print(
        "Classes selected: %d, "
        "files written: %d, "
        "functions exported: %d, "
        "failed: %d, "
        "ambiguous skipped: %d"
        % (
            stats.classes_total,
            stats.classes_written,
            stats.functions_matched,
            stats.functions_failed,
            len(stats.ambiguous),
        )
    )


# Script arguments

def parse_runtime_arguments(script_args):
    global DECOMPILE_JOBS
    global NORETURN_SEEDS_FILE
    NORETURN_SEEDS_FILE = ""
    if len(script_args) < 2:
        raise ValueError(
            "Usage: "
            "<DiffableCs> "
            "<output-directory> "
            "[whitelist|blacklist|all] "
            "[framework_ignore.txt|-] "
            "[--noreturn-seeds <path>] "
            "[--decompile-jobs <0|1|2|3|4|5|6|7|8|9|10|11|12>]"
        )

    diffable_path = script_args[0]
    output_root = script_args[1]

    selection_mode = (
        ASSEMBLY_SELECTION_MODE
    )

    ignore_file = (
        FRAMEWORK_IGNORE_FILE
    )

    argument_index = 2

    while argument_index < len(script_args):
        argument = str(
            script_args[argument_index]
        ).strip()

        lower_argument = argument.lower()

        if lower_argument in (
                "whitelist",
                "blacklist",
                "all",
                "white",
                "black",
                "allowlist",
                "denylist",
                "all-assemblies"):

            selection_mode = argument
            argument_index += 1
            continue

        if lower_argument == "--mode":
            if (
                argument_index + 1
                >= len(script_args)
            ):
                raise ValueError(
                    "--mode requires a value"
                )

            selection_mode = (
                script_args[
                    argument_index + 1
                ]
            )

            argument_index += 2
            continue

        if lower_argument == "--all-assemblies":
            selection_mode = "all"
            argument_index += 1
            continue

        if lower_argument in (
                "--blacklist",
                "--app-assemblies"):

            selection_mode = "blacklist"
            argument_index += 1
            continue

        if lower_argument in (
                "--whitelist",
                "--selected-assemblies"):

            selection_mode = "whitelist"
            argument_index += 1
            continue

        if lower_argument == "--ignore-frameworks":
            if (
                argument_index + 1
                >= len(script_args)
            ):
                raise ValueError(
                    "--ignore-frameworks "
                    "requires a path or '-'"
                )

            value = str(
                script_args[
                    argument_index + 1
                ]
            ).strip()

            if value == "-":
                ignore_file = ""
            else:
                ignore_file = value

            argument_index += 2
            continue

        if lower_argument == "--noreturn-seeds":
            if argument_index + 1 >= len(script_args):
                raise ValueError(
                    "--noreturn-seeds requires a path"
                )

            NORETURN_SEEDS_FILE = str(
                script_args[argument_index + 1]
            ).strip()
            argument_index += 2
            continue

        if lower_argument == "--decompile-jobs":
            if argument_index + 1 >= len(script_args):
                raise ValueError(
                    "--decompile-jobs requires a worker count from 0 through 12"
                )

            try:
                DECOMPILE_JOBS = int(
                    str(script_args[argument_index + 1])
                )
            except ValueError:
                raise ValueError(
                    "--decompile-jobs requires a worker count from 0 through 12"
                )

            if DECOMPILE_JOBS not in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12):
                raise ValueError(
                    "Only decompile worker counts from 0 through 12 are enabled; "
                    "higher worker counts remain gated"
                )

            argument_index += 2
            continue

        if argument == "-":
            ignore_file = ""
            argument_index += 1
            continue

        # A remaining unrecognized positional argument is treated as the
        # framework-ignore file path.
        if not ignore_file:
            ignore_file = argument
            argument_index += 1
            continue

        raise ValueError(
            "Unexpected script argument: "
            + argument
        )

    return (
        diffable_path,
        output_root,
        normalize_assembly_selection_mode(
            selection_mode
        ),
        ignore_file,
    )


# Entry point

def main():
    print(
        "Loading cpp2il classes from real directory: "
        + expand_path(
            CPP2IL_DIFFABLE_CS_DIR
        )
    )

    all_classes = load_classes_from_cpp2il_dir(
        CPP2IL_DIFFABLE_CS_DIR
    )

    framework_rules = []
    resolved_ignore_file = None

    if RUNTIME_ASSEMBLY_SELECTION_MODE == "blacklist":
        (
            framework_rules,
            resolved_ignore_file,
        ) = build_framework_ignore_rules(
            expand_path(
                CPP2IL_DIFFABLE_CS_DIR
            ),
            RUNTIME_FRAMEWORK_IGNORE_FILE,
        )

    (
        selected_classes,
        assembly_decisions,
    ) = select_classes(
        all_classes,
        SELECTED_ASSEMBLIES,
        SELECTED_CLASSES,
        RUNTIME_ASSEMBLY_SELECTION_MODE,
        framework_rules,
    )

    if not selected_classes:
        raise Exception(
            "No cpp2il classes matched the configured "
            "assembly/class filters."
        )

    included_count = len([
        item
        for item in assembly_decisions.values()
        if item[1]
    ])

    skipped_count = len([
        item
        for item in assembly_decisions.values()
        if not item[1]
    ])

    print(
        "Assembly mode: %s; "
        "included %d assemblies; "
        "skipped %d assemblies."
        % (
            RUNTIME_ASSEMBLY_SELECTION_MODE,
            included_count,
            skipped_count,
        )
    )

    if resolved_ignore_file:
        print(
            "Framework ignore file: "
            + resolved_ignore_file
        )

    elif (
        RUNTIME_ASSEMBLY_SELECTION_MODE
        == "blacklist"
    ):
        print(
            "No framework_ignore.txt found; "
            "using built-in rules only."
        )

    print(
        "Loaded %d .cs class files from directory, "
        "selected %d."
        % (
            len(all_classes),
            len(selected_classes),
        )
    )

    stats = export_classes_to_cpp(
        selected_classes,
        OUTPUT_ROOT,
        RUNTIME_ASSEMBLY_SELECTION_MODE,
        resolved_ignore_file,
        assembly_decisions,
    )

    if stats.functions_failed or stats.ambiguous:
        raise RuntimeError(
            "Export lost %d function bodies and skipped %d ambiguous functions; "
            "see the output logs."
            % (
                stats.functions_failed,
                len(stats.ambiguous),
            )
        )


try:
    runtime_args = list(
        getScriptArgs()
    )

    (
        CPP2IL_DIFFABLE_CS_DIR,
        OUTPUT_ROOT,
        RUNTIME_ASSEMBLY_SELECTION_MODE,
        RUNTIME_FRAMEWORK_IGNORE_FILE,
    ) = parse_runtime_arguments(
        runtime_args
    )

    main()

except Exception as error:
    print(
        "ERROR: "
        + str(error)
    )

    traceback.print_exc()
    raise
