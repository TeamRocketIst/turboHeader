#!/usr/bin/env python3
import ast
from pathlib import Path
import re
import time


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "ghidra_scripts" / "cpp2il_ghidra_export_editable.py"


def load_definitions():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"), filename=str(SCRIPT))
    definitions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))]
    module = ast.Module(body=definitions, type_ignores=[])
    namespace = {
        "os": __import__("os"),
        "re": re,
        "ASSEMBLY_COMMENT_PREFIX": "TurboHeader assembly: ",
        "ASSEMBLY_SELECTION_MODE": "blacklist",
        "FRAMEWORK_IGNORE_FILE": "",
        "NORETURN_SEEDS_FILE": "",
        "DECOMPILE_JOBS": 0,
        "ALLOW_SIMPLE_NAME_FALLBACK": True,
        "DUPLICATE_AMBIGUOUS_SIMPLE_MATCHES": False,
        "DECOMPILE_TIMEOUT_SECS": 60,
        "time": time,
    }
    exec(compile(module, str(SCRIPT), "exec"), namespace)
    return namespace


class FakeFunction:
    def __init__(self, name, comment=None):
        self.name = name
        self.comment = comment

    def getName(self):
        return self.name

    def getSymbol(self):
        return None

    def getComment(self):
        return self.comment


class FakeResult:
    def __init__(self, complete):
        self.complete = complete

    def decompileCompleted(self):
        return self.complete


class FakeDecompiler:
    def __init__(self, results):
        self.results = list(results)
        self.disposed = False

    def openProgram(self, _program):
        return True

    def decompileFunction(self, _function, _timeout, _monitor):
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    def dispose(self):
        self.disposed = True


class FakeAnalyzerOptions:
    BOOLEAN_TYPE = "BOOLEAN_TYPE"
    INT_TYPE = "INT_TYPE"

    def __init__(self, names, types=None):
        self.names = list(names)
        self.values = {name: True for name in names}
        self.types = types or {}

    def getOptionNames(self):
        return self.names

    def getType(self, name):
        return self.types.get(name, self.BOOLEAN_TYPE)

    def setBoolean(self, name, value):
        self.values[name] = value

    def setInt(self, name, value):
        self.values[name] = value


class FakeProgram:
    def __init__(self, options, memory=None, processor="AARCH64"):
        self.options = options
        self.memory = memory
        self.processor = processor

    def getOptions(self, category):
        assert category == "Analyzers"
        return self.options

    def getMemory(self):
        return self.memory

    def getLanguage(self):
        processor = self.processor

        class Language:
            def getProcessor(self):
                return processor

        return Language()


class FakeAnalyzer:
    def __init__(self, name, compatible=True):
        self.name = name
        self.compatible = compatible

    def canAnalyze(self, _program):
        return self.compatible


class FakeAnalysisManager:
    def __init__(self, analyzers):
        self.analyzers = analyzers
        self.scheduled = []
        self.started = []
        self.initialized = 0

    def initializeOptions(self):
        self.initialized += 1

    def getAnalyzer(self, name):
        return self.analyzers.get(name)

    def scheduleOneTimeAnalysis(self, analyzer, memory):
        self.scheduled.append((analyzer.name, memory))

    def startAnalysis(self, monitor, wait):
        self.started.append((monitor, wait))


def test_assembly_identity_resolves_homonymous_classes(ns):
    meta = ns["ClassMeta"]
    classes = [
        meta("Assembly-CSharp", "_PrivateImplementationDetails_.cs"),
        meta("Assembly-CSharp-firstpass", "_PrivateImplementationDetails_.cs"),
    ]
    index, maximum = ns["build_candidate_index"](classes)

    stats = ns["ExportStats"]()
    function = FakeFunction(
        "_PrivateImplementationDetails_$$ComputeStringHash",
        "user note\nTurboHeader assembly: Assembly-CSharp-firstpass",
    )
    matches = ns["find_matching_classes"](function, index, maximum, stats)
    assert [match.assembly for match in matches] == ["Assembly-CSharp-firstpass"]
    assert stats.assembly_ambiguities_resolved == 1
    assert stats.ambiguous == []

    legacy_stats = ns["ExportStats"]()
    assert ns["find_matching_classes"](
        FakeFunction(function.name), index, maximum, legacy_stats
    ) == []
    assert len(legacy_stats.ambiguous) == 1


def test_assembly_identity_rejects_unique_cross_assembly_match(ns):
    meta = ns["ClassMeta"]
    classes = [meta("Managed.Core", "xy.cs")]
    index, maximum = ns["build_candidate_index"](classes)

    stats = ns["ExportStats"]()
    wrong_assembly = FakeFunction(
        "XY.Toolkit.Motion$$Run",
        "TurboHeader assembly: Toolkit.Runtime",
    )
    matches = ns["find_matching_classes"](
        wrong_assembly, index, maximum, stats
    )
    assert matches == []
    assert stats.assembly_mismatches_skipped == 1
    assert stats.ambiguous == []

    matching_stats = ns["ExportStats"]()
    correct_assembly = FakeFunction(
        "XY$$Run",
        "TurboHeader assembly: Managed.Core",
    )
    matches = ns["find_matching_classes"](
        correct_assembly, index, maximum, matching_stats
    )
    assert [match.assembly for match in matches] == ["Managed.Core"]
    assert matching_stats.assembly_mismatches_skipped == 0
    assert matching_stats.ambiguous == []


def test_decompiler_is_reopened_and_retried_once(ns):
    first = FakeDecompiler([FakeResult(False)])
    replacement = FakeDecompiler([FakeResult(True)])
    ns["DecompInterface"] = lambda: replacement
    ns["currentProgram"] = object()
    stats = ns["ExportStats"]()

    active, result = ns["decompile_with_recovery"](
        first, FakeFunction("A$$Run"), object(), stats
    )

    assert active is replacement
    assert result.decompileCompleted()
    assert first.disposed
    assert stats.decompiler_restarts == 1
    assert stats.functions_recovered == 1


def test_optimized_analysis_enables_only_the_requested_analyzers(ns):
    roots = {
        "AARCH64 ELF PLT Thunks",
        "ARM Constant Reference Analyzer",
        "Subroutine References",
        "Shared Return Calls",
        "Reference",
        "ELF Scalar Operand References",
        "External Entry References",
        "Call-Fixup Installer",
        "GCC Exception Handlers",
        "Non-Returning Functions - Known",
        "Non-Returning Functions - Discovered",
    }
    suboptions = {
        "Subroutine References.Create Thunks Early": True,
        "Shared Return Calls.Assume Contiguous Functions Only": True,
        "Shared Return Calls.Allow Conditional Jumps": False,
        "Reference.Subroutine References": True,
        "Reference.Create Address Tables": False,
        "Reference.Switch Table References": False,
        "ELF Scalar Operand References.Relocation Table Guide": True,
        "GCC Exception Handlers.Create Try Catch Comments": True,
        "Non-Returning Functions - Discovered.Repair Flow Damage": True,
        "Non-Returning Functions - Discovered.Create Analysis Bookmarks": False,
        "Non-Returning Functions - Known.Create Analysis Bookmarks": False,
    }
    integer_suboptions = {
        "Non-Returning Functions - Discovered.Function Non-return Threshold": 3,
    }
    unrelated = "Decompiler Parameter ID"
    option_names = roots | set(suboptions) | set(integer_suboptions) | {unrelated}
    options = FakeAnalyzerOptions(
        option_names,
        {name: FakeAnalyzerOptions.INT_TYPE for name in integer_suboptions},
    )
    program = FakeProgram(options)
    manager = FakeAnalysisManager({})

    class ManagerProvider:
        @staticmethod
        def getAnalysisManager(actual_program):
            assert actual_program is program
            return manager

    ns["currentProgram"] = program
    ns["AutoAnalysisManager"] = ManagerProvider

    ns["configure_cpp2il_optimized_analysis"]()

    disabled_roots = {
        "GCC Exception Handlers",
        "Non-Returning Functions - Discovered",
    }
    assert all(options.values[name] for name in roots - disabled_roots)
    assert options.values["GCC Exception Handlers"] is False
    assert options.values["Non-Returning Functions - Discovered"] is False
    assert all(options.values[name] == value for name, value in suboptions.items())
    assert all(options.values[name] == value for name, value in integer_suboptions.items())
    assert options.values[unrelated] is False
    assert manager.initialized == 1


def test_global_analysis_is_limited_to_compatible_analyzers(ns):
    memory = object()
    monitor = object()
    program = FakeProgram(FakeAnalyzerOptions(set()), memory)
    manager = FakeAnalysisManager({
        "AARCH64 ELF PLT Thunks": FakeAnalyzer("AARCH64 ELF PLT Thunks"),
        "External Entry References": FakeAnalyzer("External Entry References"),
        "GCC Exception Handlers": FakeAnalyzer("GCC Exception Handlers"),
    })

    class ManagerProvider:
        @staticmethod
        def getAnalysisManager(actual_program):
            assert actual_program is program
            return manager

    ns["currentProgram"] = program
    ns["AutoAnalysisManager"] = ManagerProvider
    ns["run_optimized_global_analysis"](monitor)

    assert manager.scheduled == [
        ("AARCH64 ELF PLT Thunks", memory),
    ]
    assert manager.started == [(monitor, True)]


def test_java_noreturn_pipeline_always_disables_builtin_heuristic(ns):
    roots = {
        "Non-Returning Functions - Known",
        "Non-Returning Functions - Discovered",
    }
    options = FakeAnalyzerOptions(roots)
    program = FakeProgram(options)
    manager = FakeAnalysisManager({})

    class ManagerProvider:
        @staticmethod
        def getAnalysisManager(actual_program):
            assert actual_program is program
            return manager

    ns["currentProgram"] = program
    ns["AutoAnalysisManager"] = ManagerProvider
    ns["configure_cpp2il_optimized_analysis"]()

    assert options.values["Non-Returning Functions - Known"] is True
    assert options.values["Non-Returning Functions - Discovered"] is False


def test_non_aarch64_without_seeds_preserves_builtin_heuristic(ns):
    roots = {
        "Non-Returning Functions - Known",
        "Non-Returning Functions - Discovered",
    }
    options = FakeAnalyzerOptions(roots)
    program = FakeProgram(options, processor="x86")
    manager = FakeAnalysisManager({})

    class ManagerProvider:
        @staticmethod
        def getAnalysisManager(actual_program):
            assert actual_program is program
            return manager

    ns["currentProgram"] = program
    ns["AutoAnalysisManager"] = ManagerProvider
    ns["NORETURN_SEEDS_FILE"] = ""
    ns["configure_cpp2il_optimized_analysis"]()

    assert options.values["Non-Returning Functions - Known"] is True
    assert options.values["Non-Returning Functions - Discovered"] is True

    class Analyzer:
        @staticmethod
        def analyze(_program, _seed_path, _monitor):
            raise AssertionError("custom AArch64 analyzer ran for x86 without seeds")

    ns["Il2CppNoreturnAnalyzer"] = Analyzer
    ns["run_il2cpp_noreturn_analysis"]("", object())


def test_non_aarch64_with_seeds_uses_java_pipeline(ns):
    roots = {
        "Non-Returning Functions - Known",
        "Non-Returning Functions - Discovered",
    }
    options = FakeAnalyzerOptions(roots)
    program = FakeProgram(options, processor="x86")
    manager = FakeAnalysisManager({})

    class ManagerProvider:
        @staticmethod
        def getAnalysisManager(actual_program):
            assert actual_program is program
            return manager

    ns["currentProgram"] = program
    ns["AutoAnalysisManager"] = ManagerProvider
    ns["NORETURN_SEEDS_FILE"] = "seeds.txt"
    ns["configure_cpp2il_optimized_analysis"]()

    assert options.values["Non-Returning Functions - Known"] is True
    assert options.values["Non-Returning Functions - Discovered"] is False


def test_noreturn_seed_argument_is_parsed(ns):
    result = ns["parse_runtime_arguments"]([
        "DiffableCs",
        "output",
        "blacklist",
        "--noreturn-seeds",
        "artifacts/noreturn-seeds.txt",
    ])

    assert result == ("DiffableCs", "output", "blacklist", "")
    assert ns["NORETURN_SEEDS_FILE"] == "artifacts/noreturn-seeds.txt"


def test_staged_decompiler_jobs_one_is_explicitly_enabled(ns):
    result = ns["parse_runtime_arguments"]([
        "DiffableCs",
        "output",
        "blacklist",
        "--decompile-jobs",
        "1",
    ])

    assert result == ("DiffableCs", "output", "blacklist", "")
    assert ns["DECOMPILE_JOBS"] == 1


def test_deterministic_lane_jobs_two_is_enabled(ns):
    ns["parse_runtime_arguments"]([
        "DiffableCs",
        "output",
        "blacklist",
        "--decompile-jobs",
        "2",
    ])
    assert ns["DECOMPILE_JOBS"] == 2


def test_deterministic_lane_jobs_three_is_enabled(ns):
    ns["parse_runtime_arguments"]([
        "DiffableCs",
        "output",
        "blacklist",
        "--decompile-jobs",
        "3",
    ])
    assert ns["DECOMPILE_JOBS"] == 3


def test_gated_lane_jobs_four_is_enabled(ns):
    ns["parse_runtime_arguments"]([
        "DiffableCs",
        "output",
        "blacklist",
        "--decompile-jobs",
        "4",
    ])
    assert ns["DECOMPILE_JOBS"] == 4


def test_gated_lane_jobs_five_through_eight_are_enabled(ns):
    for worker_count in (5, 6, 7, 8):
        ns["parse_runtime_arguments"]([
            "DiffableCs",
            "output",
            "blacklist",
            "--decompile-jobs",
            str(worker_count),
        ])
        assert ns["DECOMPILE_JOBS"] == worker_count


def test_gated_lane_jobs_nine_through_twelve_are_enabled(ns):
    for worker_count in (9, 10, 11, 12):
        ns["parse_runtime_arguments"]([
            "DiffableCs",
            "output",
            "blacklist",
            "--decompile-jobs",
            str(worker_count),
        ])
        assert ns["DECOMPILE_JOBS"] == worker_count


def test_higher_worker_counts_remain_gated(ns):
    for worker_count in (13, 16):
        try:
            ns["parse_runtime_arguments"]([
                "DiffableCs",
                "output",
                "blacklist",
                "--decompile-jobs",
                str(worker_count),
            ])
        except ValueError as error:
            assert "higher worker counts remain gated" in str(error)
        else:
            raise AssertionError("worker count outside the lane gate was accepted")


def test_noreturn_work_is_delegated_to_java(ns):
    calls = []

    class Stats:
        source = lambda self: "i2c-seeds"
        provenAddresses = lambda self: 24
        markedFunctions = lambda self: 24
        callOverrides = lambda self: 3
        repairedCallers = lambda self: 2
        helperSummaries = lambda self: 0
        provenHelpers = lambda self: 0
        helpersRenamed = lambda self: 0
        helperNamesAlreadyApplied = lambda self: 0
        helperNamesPreserved = lambda self: 0
        managedInstructions = lambda self: 0
        helperInstructions = lambda self: 0
        discoverySeconds = lambda self: 0.001
        applicationSeconds = lambda self: 0.002
        totalSeconds = lambda self: 0.003

    class Analyzer:
        @staticmethod
        def analyze(program, seed_path, monitor):
            calls.append((program, seed_path, monitor))
            return Stats()

    program = object()
    monitor = object()
    ns["currentProgram"] = program
    ns["Il2CppNoreturnAnalyzer"] = Analyzer
    ns["expand_path"] = lambda path: "/resolved/" + path

    ns["run_il2cpp_noreturn_analysis"]("seeds.txt", monitor)

    assert calls == [(program, "/resolved/seeds.txt", monitor)]


def test_helper_recognition_is_delegated_to_java(ns):
    calls = []

    class Stats:
        selectedFunctions = lambda self: 3
        resolvedExports = lambda self: 4
        compilerCandidates = lambda self: 7
        provenHelpers = lambda self: 5
        ambiguousCandidates = lambda self: 0
        renamed = lambda self: 5
        alreadyNamed = lambda self: 0
        preserved = lambda self: 0
        typed = lambda self: 5
        elapsedSeconds = lambda self: 0.004

    class Analyzer:
        def __init__(self, program, functions, monitor):
            calls.append((program, functions, monitor))

        def analyze(self):
            return Stats()

    program = object()
    functions = object()
    monitor = object()
    ns["currentProgram"] = program
    ns["Il2CppExportedHelperAnalyzer"] = Analyzer

    ns["run_il2cpp_exported_helper_analysis"](functions, monitor)

    assert calls == [(program, functions, monitor)]


if __name__ == "__main__":
    definitions = load_definitions()
    test_assembly_identity_resolves_homonymous_classes(definitions)
    test_assembly_identity_rejects_unique_cross_assembly_match(definitions)
    test_decompiler_is_reopened_and_retried_once(definitions)
    test_optimized_analysis_enables_only_the_requested_analyzers(definitions)
    test_global_analysis_is_limited_to_compatible_analyzers(definitions)
    test_java_noreturn_pipeline_always_disables_builtin_heuristic(definitions)
    test_non_aarch64_without_seeds_preserves_builtin_heuristic(definitions)
    test_non_aarch64_with_seeds_uses_java_pipeline(definitions)
    test_noreturn_seed_argument_is_parsed(definitions)
    test_staged_decompiler_jobs_one_is_explicitly_enabled(definitions)
    test_deterministic_lane_jobs_two_is_enabled(definitions)
    test_deterministic_lane_jobs_three_is_enabled(definitions)
    test_gated_lane_jobs_four_is_enabled(definitions)
    test_gated_lane_jobs_five_through_eight_are_enabled(definitions)
    test_gated_lane_jobs_nine_through_twelve_are_enabled(definitions)
    test_higher_worker_counts_remain_gated(definitions)
    test_noreturn_work_is_delegated_to_java(definitions)
    test_helper_recognition_is_delegated_to_java(definitions)
    print("exporter tests passed")
