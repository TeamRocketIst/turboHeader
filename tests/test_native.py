#!/usr/bin/env python3
import json
import os
import random
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = Path(os.environ.get("TURBOHEADER_NATIVE_CLI",
                          ROOT / "native" / "build-clean" / "il2cpp_native_cli"))
FIX = ROOT / "tests" / "fixtures"

from tools.decode_i2gf import decode


def run(header, offsets=None, pointer=8):
    with tempfile.NamedTemporaryFile(suffix=".i2gf", delete=False) as tmp:
        out = Path(tmp.name)
    try:
        subprocess.run([str(CLI), str(header), str(offsets) if offsets else "-", str(out), str(pointer)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return decode(out)
    finally:
        out.unlink(missing_ok=True)


def by_name(model):
    return {s["name"]: s for s in model["structures"]}


def fields(structure):
    return [(f["offset"], f["name"], f["type"]) for f in structure["fields"]]


def test_exact_json():
    model = run(FIX / "sample.h", FIX / "type_offsets.json")
    types = by_name(model)
    assert model["pointerSize"] == 8
    assert model["offsetSource"] == "typeOffsetsJson"
    assert model["offsetSchemaVersion"] == 3
    assert model["missingOffsets"] == 0
    assert all(f["offsetEvidence"] in {"sidecarCopied", "abiDefined"}
               for name in ("Base_o", "Vec2_o", "Derived_o", "Vec2_Fields")
               for f in types[name]["fields"])
    assert set(types) == {
        "Base_o", "Base_c", "Vec2_o", "Derived_o", "Derived_c", "Vec2_Fields",
    }
    assert fields(types["Base_c"]) == [(0, "unused", "void*")]
    assert fields(types["Derived_c"]) == [(0, "unused", "void*")]
    assert types["Base_o"]["length"] == 20
    assert fields(types["Base_o"]) == [
        (0, "klass", "struct Base_c *"),
        (8, "monitor", "void *"),
        (16, "a", "int32_t"),
    ]
    assert types["Vec2_o"]["length"] == 8
    assert fields(types["Vec2_o"]) == [(0, "x", "float"), (4, "y", "float")]
    assert types["Vec2_Fields"]["length"] == 8
    assert fields(types["Vec2_Fields"]) == [(0, "x", "float"), (4, "y", "float")]
    assert types["Derived_o"]["length"] == 60
    assert fields(types["Derived_o"]) == [
        (0, "klass", "struct Derived_c *"),
        (8, "monitor", "void *"),
        (24, "position", "struct Vec2_Fields"),
        (32, "values", "int32_t[3]"),
        (44, "overlapA", "int32_t"),
        (44, "overlapB", "float"),
        (48, "wide", "int64_t"),
        (52, "tail", "int32_t"),
        (56, "a", "int32_t"),
    ]


def test_dumpcs_matches_json():
    a = run(FIX / "sample.h", FIX / "type_offsets.json")
    b = run(FIX / "sample.h", FIX / "dump.cs")
    assert [(s["name"], s["length"], fields(s)) for s in a["structures"]] == [
        (s["name"], s["length"], fields(s)) for s in b["structures"]]
    assert a["offsetSource"] == "typeOffsetsJson"
    assert b["offsetSource"] == "dumpCs"


def test_converted_super_inheritance_matches_original():
    converted = (FIX / "sample.h").read_text().replace(
        "struct Derived_Fields : Base_Fields {",
        "struct Derived_Fields {\n    Base_Fields super;",
    )
    with tempfile.TemporaryDirectory() as td:
        header = Path(td) / "il2cpp_ghidra.h"
        header.write_text(converted)
        converted_model = run(header, FIX / "type_offsets.json")
    assert converted_model == run(FIX / "sample.h", FIX / "type_offsets.json")


def test_natural_layout_32_and_64():
    raw64 = run(FIX / "sample.h", None, 8)
    raw32 = run(FIX / "sample.h", None, 4)
    assert raw64["offsetSource"] == raw32["offsetSource"] == "headerOnly"
    assert all(f["offsetEvidence"] in {"headerInferred", "abiDefined"}
               for model in (raw64, raw32) for structure in model["structures"]
               for f in structure["fields"])
    m64 = by_name(raw64)
    m32 = by_name(raw32)
    assert fields(m64["Base_o"])[:2] == [(0, "klass", "struct Base_c *"), (8, "monitor", "void *")]
    assert fields(m32["Base_o"])[:2] == [(0, "klass", "struct Base_c *"), (4, "monitor", "void *")]
    assert m64["Derived_o"]["length"] >= m32["Derived_o"]["length"]


def test_schema_v2_pointer_size_and_v1_compatibility():
    header = """
struct Ref32_c { void *unused; };
struct Ref32_Fields { int32_t invalidHeader; int32_t first; int32_t staticOnly; };
struct Ref32_o { struct Ref32_c *klass; void *monitor; struct Ref32_Fields fields; };
struct Empty32_c { void *unused; };
struct Empty32_Fields {};
struct Empty32_o { struct Empty32_c *klass; void *monitor; struct Empty32_Fields fields; };
"""
    version2 = {"version": 2, "pointerSize": 4, "types": {
        "Ref32": {
            "fields": {"invalidHeader": 0, "first": 8},
            "staticFields": {"staticOnly": 40},
        },
        "Empty32": {"fields": {}},
    }}
    version1 = dict(version2)
    version1.pop("version")
    version1.pop("pointerSize")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        h = root / "pointer32.h"
        v2 = root / "pointer32-v2.json"
        v1 = root / "pointer32-v1.json"
        mismatch = root / "mismatch.i2gf"
        h.write_text(header)
        v2.write_text(json.dumps(version2))
        v1.write_text(json.dumps(version1))

        model_v2 = run(h, v2, 4)
        model_v1 = run(h, v1, 4)
        result = subprocess.run(
            [str(CLI), str(h), str(v2), str(mismatch), "8"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    types = by_name(model_v2)
    assert model_v2["pointerSize"] == 4
    assert model_v2["offsetSchemaVersion"] == 2
    assert fields(types["Ref32_o"]) == [
        (0, "klass", "struct Ref32_c *"),
        (4, "monitor", "void *"),
        (8, "first", "int32_t"),
    ]
    assert fields(types["Empty32_o"]) == [
        (0, "klass", "struct Empty32_c *"),
        (4, "monitor", "void *"),
    ]
    assert "Ref32_StaticFields" not in types
    assert model_v2["missingOffsetReasons"]["objectHeaderOffset"] == 1
    assert model_v2["missingOffsetReasons"]["unsupportedLayout"] == 1

    assert model_v1["offsetSchemaVersion"] == 0
    assert model_v1["structures"] == model_v2["structures"]
    assert model_v1["missingOffsetReasons"] == model_v2["missingOffsetReasons"]
    assert result.returncode == 1
    assert "pointer size 4 does not match target pointer size 8" in result.stderr


def test_missing_offsets_are_counted_and_skipped():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "partial.json"
        p.write_text(json.dumps({"types": {"Base": {"fields": {"a": 16}},
                                                   "Derived": {"fields": {"a": 56}}}}))
        model = run(FIX / "sample.h", p)
        assert model["missingOffsets"] == 8
        assert sum(model["missingOffsetReasons"].values()) == model["missingOffsets"]
        derived = by_name(model)["Derived_o"]
        assert [f["name"] for f in derived["fields"]] == ["klass", "monitor", "a"]
        assert all(f["offsetEvidence"] != "headerInferred" for f in derived["fields"])


def test_empty_sidecar_does_not_enable_header_inference():
    with tempfile.TemporaryDirectory() as td:
        sidecar = Path(td) / "empty.json"
        sidecar.write_text(json.dumps({"version": 3, "pointerSize": 8, "types": {}}))
        decoded = run(FIX / "sample.h", sidecar)
    assert decoded["offsetSource"] == "typeOffsetsJson"
    assert decoded["missingOffsets"] > 0
    assert all(f["offsetEvidence"] != "headerInferred"
               for structure in decoded["structures"]
               if structure["name"].endswith(("_o", "_Fields"))
               for f in structure["fields"])


def test_partial_sidecar_never_infers_transitive_value_offsets():
    header = """
struct PartialValue_Fields { int32_t first; int32_t second; };
struct PartialValue_o { struct PartialValue_Fields fields; };
struct PartialHolder_c { void *unused; };
struct PartialHolder_Fields { struct PartialValue_o value; };
struct PartialHolder_o {
    struct PartialHolder_c *klass;
    void *monitor;
    struct PartialHolder_Fields fields;
};
"""
    offsets = {"version": 2, "pointerSize": 8, "types": {
        "PartialValue": {"fields": {"first": 0}},
        "PartialHolder": {"fields": {"value": 16}},
    }}
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "partial-transitive.h"
        j = Path(td) / "partial-transitive.json"
        h.write_text(header)
        j.write_text(json.dumps(offsets))
        decoded = run(h, j)
    model = by_name(decoded)
    assert decoded["missingOffsets"] == 2
    assert fields(model["PartialValue_Fields"]) == [(0, "first", "int32_t")]
    assert all(f["offsetEvidence"] == "sidecarCopied"
               for f in model["PartialValue_Fields"]["fields"])


def test_schema_v3_instance_size_is_preserved_as_sidecar_evidence():
    header = """
struct Sized_c { void *unused; };
struct Sized_Fields { int32_t value; };
struct Sized_o { struct Sized_c *klass; void *monitor; struct Sized_Fields fields; };
struct SizedValue_Fields { int32_t value; };
struct SizedValue_o { struct SizedValue_Fields fields; };
"""
    offsets = {"version": 3, "pointerSize": 8, "types": {
        "Sized": {"instanceSize": 32, "fields": {"value": 16}},
        "SizedValue": {"instanceSize": 8, "fields": {"value": 0}},
    }}
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "sized.h"
        j = Path(td) / "sized.json"
        h.write_text(header)
        j.write_text(json.dumps(offsets))
        decoded = run(h, j)
    model = by_name(decoded)
    assert decoded["offsetSchemaVersion"] == 3
    assert model["Sized_o"]["length"] == 32
    assert model["Sized_o"]["lengthEvidence"] == "sidecarCopied"
    assert model["SizedValue_o"]["length"] == 8
    assert model["SizedValue_o"]["lengthEvidence"] == "sidecarCopied"


def test_partial_value_uses_instance_size_without_laying_out_omitted_fields():
    header = """
struct PartialExact_Fields { int64_t first; int64_t omitted; };
struct PartialExact_o { struct PartialExact_Fields fields; };
struct ExactHolder_c { void *unused; };
struct ExactHolder_Fields { struct PartialExact_o value; int32_t tail; };
struct ExactHolder_o {
    struct ExactHolder_c *klass;
    void *monitor;
    struct ExactHolder_Fields fields;
};
"""
    offsets = {"version": 3, "pointerSize": 8, "types": {
        "PartialExact": {"instanceSize": 8, "fields": {"first": 0}},
        "ExactHolder": {"instanceSize": 28, "fields": {"value": 16, "tail": 24}},
    }}
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "partial-exact.h"
        j = Path(td) / "partial-exact.json"
        h.write_text(header)
        j.write_text(json.dumps(offsets))
        decoded = run(h, j)
    model = by_name(decoded)
    assert decoded["missingOffsets"] == 2
    assert model["PartialExact_Fields"]["length"] == 8
    assert model["PartialExact_Fields"]["lengthEvidence"] == "sidecarCopied"
    assert fields(model["PartialExact_Fields"]) == [(0, "first", "int64_t")]
    assert model["ExactHolder_o"]["length"] == 28
    assert model["ExactHolder_o"]["lengthEvidence"] == "sidecarCopied"


def test_inferred_parent_extent_uses_nested_sidecar_size():
    header = """
struct PaddedValue_Fields { uint16_t length; uint8_t buffer[30]; };
struct PaddedValue_o { struct PaddedValue_Fields fields; };
struct PaddedHolder_c { void *unused; };
struct PaddedHolder_Fields { struct PaddedValue_o value; };
struct PaddedHolder_o {
    struct PaddedHolder_c *klass;
    void *monitor;
    struct PaddedHolder_Fields fields;
};
"""
    offsets = {"version": 3, "pointerSize": 8, "types": {
        "PaddedValue": {"instanceSize": 40, "fields": {"length": 0, "buffer": 8}},
        "PaddedHolder": {"fields": {"value": 16}},
    }}
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "nested-size.h"
        j = Path(td) / "nested-size.json"
        h.write_text(header)
        j.write_text(json.dumps(offsets))
        decoded = run(h, j)
    model = by_name(decoded)
    assert model["PaddedValue_o"]["length"] == 40
    assert model["PaddedValue_o"]["lengthEvidence"] == "sidecarCopied"
    assert model["PaddedHolder_o"]["length"] == 56
    assert model["PaddedHolder_o"]["lengthEvidence"] == "headerInferred"


def test_inconsistent_instance_size_is_downgraded_to_inferred_extent():
    header = """
struct TooSmall_Fields { int64_t value; };
struct TooSmall_o { struct TooSmall_Fields fields; };
"""
    offsets = {"version": 3, "pointerSize": 8, "types": {
        "TooSmall": {"instanceSize": 8, "fields": {"value": 4}},
    }}
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "too-small.h"
        j = Path(td) / "too-small.json"
        h.write_text(header)
        j.write_text(json.dumps(offsets))
        decoded = run(h, j)
    structure = by_name(decoded)["TooSmall_o"]
    assert structure["length"] == 12
    assert structure["lengthEvidence"] == "headerInferred"
    assert fields(structure) == [(4, "value", "int64_t")]


def test_empty_value_dependency_terminates_and_header_only_reference_is_kept():
    header = """
struct Empty_c { void *unused; };
struct Empty_Fields {};
struct Empty_o { struct Empty_c *klass; void *monitor; struct Empty_Fields fields; };
struct Holder_c { void *unused; };
struct Holder_Fields { struct Empty_o value; };
struct Holder_o { struct Holder_c *klass; void *monitor; struct Holder_Fields fields; };
struct HeaderOnly_c { void *unused; };
struct HeaderOnly_o { struct HeaderOnly_c *klass; void *monitor; };
"""
    offsets = {"types": {"Holder": {"fields": {"value": 16}}}}
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "empty.h"
        j = Path(td) / "empty.json"
        h.write_text(header)
        j.write_text(json.dumps(offsets))
        model = by_name(run(h, j))
    assert fields(model["HeaderOnly_o"]) == [
        (0, "klass", "struct HeaderOnly_c *"),
        (8, "monitor", "void *"),
    ]
    assert model["HeaderOnly_o"]["length"] == 16
    assert fields(model["Holder_o"])[-1] == (16, "value", "struct Empty_Fields")
    assert model["Empty_Fields"]["fields"] == []
    assert model["Empty_Fields"]["length"] == 1


def test_nested_value_layout_survives_layout_cache_growth():
    definitions = ["struct Nested11_Fields { int32_t value; };"]
    for index in range(10, -1, -1):
        definitions.append(
            f"struct Nested{index}_Fields {{ struct Nested{index + 1}_Fields value; }};"
        )
    definitions.extend([
        "struct NestedRoot_c { void *unused; };",
        "struct NestedRoot_Fields { struct Nested0_Fields value; };",
        "struct NestedRoot_o { struct NestedRoot_c *klass; void *monitor; "
        "struct NestedRoot_Fields fields; };",
    ])
    with tempfile.TemporaryDirectory() as td:
        header = Path(td) / "nested.h"
        header.write_text("\n".join(definitions))
        model = by_name(run(header))
    assert model["Nested0_Fields"]["length"] == 4
    assert fields(model["Nested0_Fields"]) == [
        (0, "value", "struct Nested1_Fields"),
    ]


def test_empty_value_object_is_not_dropped():
    header = """
struct EmptyValue_Fields {};
struct EmptyValue_o { struct EmptyValue_Fields fields; };
"""
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "empty-value.h"
        h.write_text(header)
        model = by_name(run(h))
    assert "EmptyValue_o" in model
    assert model["EmptyValue_o"]["fields"] == []
    assert model["EmptyValue_o"]["length"] == 1


def test_reference_header_collision_is_skipped_but_value_offset_zero_is_valid():
    header = """
struct Value_Fields { int32_t first; };
struct Ref_c { void *unused; };
struct Ref_Fields { int32_t bad; struct Value_Fields value; };
struct Ref_o { struct Ref_c *klass; void *monitor; struct Ref_Fields fields; };
"""
    offsets = {"types": {
        "Value": {"fields": {"first": 0}},
        "Ref": {"fields": {"bad": 0, "value": 16}},
    }}
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "collision.h"
        j = Path(td) / "collision.json"
        h.write_text(header)
        j.write_text(json.dumps(offsets))
        decoded = run(h, j)
    model = by_name(decoded)
    assert decoded["missingOffsets"] == 1
    assert decoded["missingOffsetReasons"]["objectHeaderOffset"] == 1
    assert [field["name"] for field in model["Ref_o"]["fields"]] == [
        "klass", "monitor", "value",
    ]
    assert fields(model["Value_Fields"]) == [(0, "first", "int32_t")]


def test_schema_v2_missing_offset_categories_are_structural_and_exhaustive():
    header = """
struct Open_c { void *unused; };
struct Open_Fields { int32_t openValue; };
struct Open_o { struct Open_c *klass; void *monitor; struct Open_Fields fields; };
struct Parent_Fields { int32_t inherited; };
struct Concrete_c { void *unused; };
struct Concrete_Fields : Parent_Fields { int32_t own; };
struct Concrete_o { struct Concrete_c *klass; void *monitor; struct Concrete_Fields fields; };
struct Absent_c { void *unused; };
struct Absent_Fields { int32_t value; };
struct Absent_o { struct Absent_c *klass; void *monitor; struct Absent_Fields fields; };
struct Collision_c { void *unused; };
struct Collision_Fields { int32_t value; };
struct Collision_o { struct Collision_c *klass; void *monitor; struct Collision_Fields fields; };
struct Unsupported_c { void *unused; };
struct Unsupported_Fields { int32_t value; };
struct Unsupported_o { struct Unsupported_c *klass; void *monitor; struct Unsupported_Fields fields; };
"""
    offsets = {"version": 2, "pointerSize": 8, "types": {
        "Open": {
            "layoutProvenance": "unresolvedOpenGeneric", "fields": {},
            "unresolvedFields": {"openValue": "openGenericLayout"},
        },
        "Parent": {
            "layoutProvenance": "unresolvedOpenGeneric", "fields": {},
            "unresolvedFields": {"inherited": "openGenericLayout"},
        },
        "Concrete": {"layoutProvenance": "metadata", "fields": {"own": 20}},
        "Collision": {"layoutProvenance": "metadata", "fields": {"value": 0}},
        "Unsupported": {"layoutProvenance": "metadata", "fields": {}},
    }}
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "categories.h"
        j = Path(td) / "categories.json"
        h.write_text(header)
        j.write_text(json.dumps(offsets))
        decoded = run(h, j)
    assert decoded["missingOffsets"] == 5
    assert decoded["missingOffsetReasons"] == {
        "openGenericDefinition": 1,
        "concreteInstanceAbsent": 1,
        "unresolvedGenericParent": 1,
        "objectHeaderOffset": 1,
        "unsupportedLayout": 1,
        "legacyUnclassified": 0,
    }
    assert sum(decoded["missingOffsetReasons"].values()) == decoded["missingOffsets"]


def test_static_json_offsets_do_not_override_instance_offsets():
    header = """
struct Mixed_StaticFields { int32_t x; int32_t onlyStatic; };
struct Mixed_c { struct Mixed_StaticFields *static_fields; };
struct Mixed_Fields { int32_t x; int32_t onlyStatic; };
struct Mixed_o { struct Mixed_c *klass; void *monitor; struct Mixed_Fields fields; };
"""
    offsets = {"types": {"Mixed": {
        "fields": {"x": 16},
        "staticFields": {"x": 0, "onlyStatic": 24},
    }}}
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "static.h"
        j = Path(td) / "static.json"
        h.write_text(header)
        j.write_text(json.dumps(offsets))
        decoded = run(h, j)
    assert decoded["missingOffsets"] == 1
    assert fields(by_name(decoded)["Mixed_o"]) == [
        (0, "klass", "struct Mixed_c *"),
        (8, "monitor", "void *"),
        (16, "x", "int32_t"),
    ]
    assert fields(by_name(decoded)["Mixed_StaticFields"]) == [
        (0, "x", "int32_t"),
        (24, "onlyStatic", "int32_t"),
    ]


def test_dumpcs_static_fields_are_not_used_as_instance_offsets():
    header = """
struct DumpMixed_StaticFields { int32_t shared; void *threadValue; };
struct DumpMixed_c { struct DumpMixed_StaticFields *static_fields; };
struct DumpMixed_Fields { int32_t instance; int32_t shared; };
struct DumpMixed_o { struct DumpMixed_c *klass; void *monitor; struct DumpMixed_Fields fields; };
"""
    dump = """
// Namespace:
public class DumpMixed
{
    private int instance; // 0x10
    private static int shared; // 0x0
    private static object threadValue; // 0x80000000
}
"""
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "static.h"
        cs = Path(td) / "dump.cs"
        h.write_text(header)
        cs.write_text(dump)
        decoded = run(h, cs)
    model = by_name(decoded)
    assert decoded["missingOffsets"] == 2
    assert decoded["missingOffsetReasons"]["unsupportedLayout"] == 2
    assert fields(model["DumpMixed_o"]) == [
        (0, "klass", "struct DumpMixed_c *"),
        (8, "monitor", "void *"),
        (16, "instance", "int32_t"),
    ]
    assert fields(model["DumpMixed_StaticFields"]) == [(0, "shared", "int32_t")]
    assert model["DumpMixed_StaticFields"]["length"] == 4


def test_thread_static_only_storage_stays_opaque_and_is_reported():
    header = """
struct ThreadOnly_StaticFields { void *cache; int32_t generation; };
struct ThreadOnly_c { struct ThreadOnly_StaticFields *static_fields; };
struct ThreadOnly_Fields { int32_t instance; };
struct ThreadOnly_o { struct ThreadOnly_c *klass; void *monitor; struct ThreadOnly_Fields fields; };
"""
    offsets = {"types": {"ThreadOnly": {
        "fields": {"instance": 16},
        "staticFields": {"cache": 0x80000000, "generation": 0x80000001},
    }}}
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "thread-only.h"
        j = Path(td) / "thread-only.json"
        h.write_text(header)
        j.write_text(json.dumps(offsets))
        decoded = run(h, j)
    model = by_name(decoded)
    assert "ThreadOnly_StaticFields" not in model
    assert decoded["missingOffsets"] == 2
    assert decoded["missingOffsetReasons"]["unsupportedLayout"] == 2


def test_header_only_static_fields_match_full_header_layout():
    decoded = run(FIX / "class_metadata.h")
    model = by_name(decoded)
    assert decoded["offsetSource"] == "headerOnly"
    assert fields(model["Cipher_StaticFields"]) == [
        (0, "state", "int32_t"),
        (4, "value", "struct Cipher_StaticValue"),
        (8, "helper", "struct Cipher_Helper*"),
        (16, "offsets", "struct Fixture_Int32_array*"),
        (24, "decoy", "struct LooksLikeArrayButIsNot*"),
        (32, "external", "struct ExternalState*"),
        (40, "thread_cache", "void*"),
    ]
    assert all(field["offsetEvidence"] == "headerInferred"
               for field in model["Cipher_StaticFields"]["fields"])
    assert fields(model["Cipher_Helper"]) == [
        (0, "value", "int32_t"),
        (8, "next", "struct Cipher_Helper*"),
    ]


def test_invalid_numeric_offsets_are_rejected():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        for value in (-1, 0x01000001, 0x10000001):
            offsets = td / f"bad-{value}.json"
            output = td / f"bad-{value}.i2gf"
            offsets.write_text(json.dumps({"types": {"Base": {"fields": {"a": value}}}}))
            result = subprocess.run(
                [str(CLI), str(FIX / "sample.h"), str(offsets), str(output), "8"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            assert result.returncode == 1
            assert "invalid type_offsets.json" in result.stderr


def test_cumulative_sidecar_layout_budget_fails_closed():
    definitions = []
    types = {}
    for index in range(33):
        definitions.extend([
            f"struct Budget{index}_c {{ void *unused; }};",
            f"struct Budget{index}_Fields {{ int32_t value; }};",
            f"struct Budget{index}_o {{ struct Budget{index}_c *klass; void *monitor; "
            f"struct Budget{index}_Fields fields; }};",
        ])
        types[f"Budget{index}"] = {"fields": {"value": 0x01000000 - 4}}
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        header = root / "budget.h"
        offsets = root / "budget.json"
        output = root / "budget.i2gf"
        header.write_text("\n".join(definitions))
        offsets.write_text(json.dumps({"types": dict(list(types.items())[:32])}))
        accepted = subprocess.run(
            [str(CLI), str(header), str(offsets), str(output), "8"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        assert accepted.returncode == 0, accepted.stderr
        offsets.write_text(json.dumps({"types": types}))
        result = subprocess.run(
            [str(CLI), str(header), str(offsets), str(output), "8"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    assert result.returncode == 1
    assert "cumulative layout size exceeds limit" in result.stderr


def test_type_offsets_resource_limits_fail_closed():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        output = td / "out.i2gf"

        accepted_depth = td / "accepted-depth.json"
        accepted_depth.write_text(
            '{"ignored":' + '[' * 64 + '0' + ']' * 64 + ',"types":{}}'
        )
        accepted = subprocess.run(
            [str(CLI), str(FIX / "sample.h"), str(accepted_depth), str(output), "8"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        assert accepted.returncode == 0, accepted.stderr

        excessive_depth = td / "excessive-depth.json"
        excessive_depth.write_text(
            '{"ignored":' + '[' * 65 + '0' + ']' * 65 + ',"types":{}}'
        )
        rejected = subprocess.run(
            [str(CLI), str(FIX / "sample.h"), str(excessive_depth), str(output), "8"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        assert rejected.returncode == 1
        assert "nesting exceeds limit" in rejected.stderr

        oversized = td / "oversized.json"
        with oversized.open("wb") as stream:
            stream.truncate(128 * 1024 * 1024 + 1)
        rejected = subprocess.run(
            [str(CLI), str(FIX / "sample.h"), str(oversized), str(output), "8"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        assert rejected.returncode == 1
        assert "exceeds 134217728 byte limit" in rejected.stderr

        long_string = td / "long-string.json"
        long_string.write_text('{"ignored":"' + 'a' * (1024 * 1024 + 1) + '","types":{}}')
        rejected = subprocess.run(
            [str(CLI), str(FIX / "sample.h"), str(long_string), str(output), "8"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        assert rejected.returncode == 1
        assert "string exceeds limit" in rejected.stderr


def test_type_offsets_reject_ambiguous_or_invalid_json():
    cases = [
        ('{"types":{},"types":{}}', "duplicate types object"),
        ('{"version":2,"version":2,"pointerSize":8,"types":{}}',
         "duplicate version"),
        ('{"version":2,"pointerSize":8,"pointerSize":8,"types":{}}',
         "duplicate pointerSize"),
        ('{"types":{"Base":{"fields":{}},"Base":{"fields":{}}}}',
         "duplicate type"),
        ('{"types":{"Base":{"fields":{},"fields":{}}}}',
         "duplicate type property"),
        ('{"types":{"Base":{"fields":{"a":16,"a":20}}}}',
         "duplicate field"),
        ('{"types":{}} trailing', "trailing data"),
        ('{"ignored":"\\q","types":{}}', "invalid escape"),
        ('{"ignored":"\\u12xz","types":{}}', "invalid Unicode escape"),
        ('{"ignored":"\\u0000","types":{}}', "strings cannot contain NUL"),
        ('{"types":{"Base":{"fields":{"a":01}}}}', "invalid type_offsets.json"),
        ('{"types":{"Base":{"fields":{"a":null}}}}', "invalid type_offsets.json"),
    ]
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        for index, (payload, expected) in enumerate(cases):
            offsets = td / f"invalid-{index}.json"
            output = td / f"invalid-{index}.i2gf"
            offsets.write_text(payload)
            result = subprocess.run(
                [str(CLI), str(FIX / "sample.h"), str(offsets), str(output), "8"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            assert result.returncode == 1, (index, result.stderr)
            assert expected in result.stderr, (index, result.stderr)


def test_unknown_json_properties_are_validated_and_ignored():
    with tempfile.TemporaryDirectory() as td:
        offsets = Path(td) / "forward-compatible.json"
        offsets.write_text(json.dumps({
            "future": {"enabled": True, "ratio": 1.25, "unset": None,
                       "values": [-2, 3.5e4, "ok"]},
            "types": {},
        }))
        decoded = run(FIX / "sample.h", offsets)
    assert decoded["offsetSource"] == "typeOffsetsJson"


def test_unsupported_json_schema_and_early_instance_size_are_rejected():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        cases = [
            ({"version": 4, "pointerSize": 8, "types": {}},
             "unsupported type_offsets.json schema version 4"),
            ({"version": 2, "pointerSize": 8,
              "types": {"Base": {"instanceSize": 20, "fields": {"a": 16}}}},
             "instanceSize requires schema version 3"),
        ]
        for index, (payload, error) in enumerate(cases):
            offsets = td / f"schema-{index}.json"
            output = td / f"schema-{index}.i2gf"
            offsets.write_text(json.dumps(payload))
            result = subprocess.run(
                [str(CLI), str(FIX / "sample.h"), str(offsets), str(output), "8"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            assert result.returncode == 1
            assert error in result.stderr


def test_recursive_value_alignment_is_used_for_natural_layout():
    header = """
struct Aligned_Fields { double wide; uint8_t tail; };
struct Holder_c { void *unused; };
struct Holder_Fields { uint8_t prefix; struct Aligned_Fields nested; uint8_t suffix; };
struct Holder_o { struct Holder_c *klass; void *monitor; struct Holder_Fields fields; };
"""
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "alignment.h"
        h.write_text(header)
        model = by_name(run(h))
    assert model["Aligned_Fields"]["length"] == 16
    assert fields(model["Holder_o"]) == [
        (0, "klass", "struct Holder_c *"),
        (8, "monitor", "void *"),
        (16, "prefix", "uint8_t"),
        (24, "nested", "struct Aligned_Fields"),
        (40, "suffix", "uint8_t"),
    ]


def test_recursive_value_cycle_terminates_conservatively():
    header = """
struct A_Fields { struct B_o b; };
struct B_Fields { struct A_o a; };
struct Root_c { void *unused; };
struct Root_Fields { struct A_o value; };
struct Root_o { struct Root_c *klass; void *monitor; struct Root_Fields fields; };
"""
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "cycle.h"
        h.write_text(header)
        model = by_name(run(h))
    assert fields(model["Root_o"])[-1] == (16, "value", "struct A_Fields")
    assert model["A_Fields"]["length"] == 8
    assert model["B_Fields"]["length"] == 8


def test_multidimensional_arrays_and_function_pointers_are_preserved():
    header = """
struct Declarators_c { void *unused; };
struct Declarators_Fields {
    int16_t matrix[2][3];
    void (*callback)(int32_t, void *);
    void (*handlers[2])(int32_t);
    uint8_t tail;
};
struct Declarators_o { struct Declarators_c *klass; void *monitor; struct Declarators_Fields fields; };
"""
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "declarators.h"
        h.write_text(header)
        model = by_name(run(h))
    assert fields(model["Declarators_o"]) == [
        (0, "klass", "struct Declarators_c *"),
        (8, "monitor", "void *"),
        (16, "matrix", "int16_t[2][3]"),
        (32, "callback", "void (*)(int32_t, void*)"),
        (40, "handlers", "void (*)(int32_t)[2]"),
        (56, "tail", "uint8_t"),
    ]


def test_invalid_or_overflowing_array_dimensions_fail_closed():
    declarations = [
        "uint8_t bad[0];",
        "uint8_t bad[4294967296];",
        "uint64_t bad[100000000];",
    ]
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        for index, declaration in enumerate(declarations):
            header = td / f"bad-{index}.h"
            output = td / f"bad-{index}.i2gf"
            header.write_text(f"""
struct Bad_c {{ void *unused; }};
struct Bad_Fields {{ {declaration} }};
struct Bad_o {{ struct Bad_c *klass; void *monitor; struct Bad_Fields fields; }};
""")
            result = subprocess.run(
                [str(CLI), str(header), "-", str(output), "8"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            assert result.returncode == 1, (declaration, result.stderr)
            assert "model build failed" in result.stderr


def test_nested_anonymous_structs_and_unions_have_stable_structural_types():
    header = """
struct Anonymous_c { void *unused; };
struct Anonymous_Fields {
    uint8_t prefix;
    struct { uint16_t small; uint32_t wide; } pair;
    union { uint32_t raw; float number; uint8_t bytes[4]; } choice;
    struct { uint16_t value; } items[2];
    uint8_t tail;
};
struct Anonymous_o { struct Anonymous_c *klass; void *monitor; struct Anonymous_Fields fields; };
"""
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "anonymous.h"
        h.write_text(header)
        model = by_name(run(h))

    pair_name = "Anonymous_Fields__anonymous_1_Fields"
    choice_name = "Anonymous_Fields__anonymous_2_Fields"
    items_name = "Anonymous_Fields__anonymous_3_Fields"
    assert fields(model["Anonymous_o"]) == [
        (0, "klass", "struct Anonymous_c *"),
        (8, "monitor", "void *"),
        (16, "prefix", "uint8_t"),
        (20, "pair", f"struct {pair_name}"),
        (28, "choice", f"struct {choice_name}"),
        (32, "items", f"struct {items_name}[2]"),
        (36, "tail", "uint8_t"),
    ]
    assert model[pair_name]["length"] == 8
    assert fields(model[pair_name]) == [(0, "small", "uint16_t"), (4, "wide", "uint32_t")]
    assert model[choice_name]["length"] == 4
    assert fields(model[choice_name]) == [
        (0, "raw", "uint32_t"),
        (0, "number", "float"),
        (0, "bytes", "uint8_t[4]"),
    ]
    assert model[items_name]["length"] == 2
    assert fields(model[items_name]) == [(0, "value", "uint16_t")]


def test_bitfields_fail_with_a_precise_parser_error():
    header = """
struct Flags_c { void *unused; };
struct Flags_Fields { uint32_t enabled : 1; };
struct Flags_o { struct Flags_c *klass; void *monitor; struct Flags_Fields fields; };
"""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        h = td / "bitfield.h"
        output = td / "bitfield.i2gf"
        h.write_text(header)
        result = subprocess.run(
            [str(CLI), str(h), "-", str(output), "8"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    assert result.returncode == 1
    assert result.stderr.strip() == "bitfield declarations are unsupported in Flags_Fields"


def test_promoted_anonymous_union_is_preserved_as_a_stable_nested_type():
    header = """
struct Promoted_c { void *unused; };
struct Promoted_Fields {
    union { uint32_t raw; float number; };
    uint8_t tail;
};
struct Promoted_o { struct Promoted_c *klass; void *monitor; struct Promoted_Fields fields; };
"""
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "promoted.h"
        h.write_text(header)
        model = by_name(run(h))
    nested = "Promoted_Fields__anonymous_0_Fields"
    assert fields(model["Promoted_o"])[-2:] == [
        (16, "__anonymous_0", f"struct {nested}"),
        (20, "tail", "uint8_t"),
    ]
    assert fields(model[nested]) == [(0, "raw", "uint32_t"), (0, "number", "float")]


def test_class_vtable_and_static_fields_graph_is_emitted_selectively():
    decoded = run(FIX / "class_metadata.h", FIX / "class_metadata_offsets.json")
    model = by_name(decoded)

    assert decoded["missingOffsets"] == 1
    assert decoded["missingOffsetReasons"]["unsupportedLayout"] == 1
    assert fields(model["Cipher_o"]) == [
        (0, "klass", "struct Cipher_c *"),
        (8, "monitor", "void *"),
        (16, "keySize", "int32_t"),
    ]
    assert fields(model["Cipher_c"]) == [
        (0, "_1", "struct Il2CppClass_1"),
        (16, "static_fields", "struct Cipher_StaticFields*"),
        (24, "rgctx_data", "void*"),
        (32, "_2", "struct Il2CppClass_2"),
        (40, "vtable", "struct Cipher_VTable"),
    ]
    assert model["Cipher_c"]["length"] == 72
    assert fields(model["Cipher_VTable"]) == [
        (0, "_0_Transform", "struct VirtualInvokeData"),
        (16, "_1_Reset", "struct VirtualInvokeData"),
    ]
    assert fields(model["VirtualInvokeData"]) == [
        (0, "methodPtr", "void (*)(void)"),
        (8, "method", "void*"),
    ]
    assert fields(model["Cipher_StaticFields"]) == [
        (0, "state", "int32_t"),
        (4, "value", "struct Cipher_StaticValue"),
        (8, "helper", "struct Cipher_Helper*"),
        (16, "offsets", "struct Fixture_Int32_array*"),
        (24, "decoy", "struct LooksLikeArrayButIsNot*"),
        (32, "external", "struct ExternalState*"),
    ]
    assert model["Cipher_StaticFields"]["length"] == 40
    assert model["Cipher_StaticFields"]["lengthEvidence"] == "headerInferred"
    assert all(field["offsetEvidence"] == "sidecarCopied"
               for field in model["Cipher_StaticFields"]["fields"])
    assert fields(model["Cipher_StaticValue"]) == [(0, "tag", "uint32_t")]
    assert fields(model["Fixture_Int32_array"]) == [
        (0, "obj", "struct Il2CppObject"),
        (16, "bounds", "struct Il2CppArrayBounds*"),
        (24, "max_length", "il2cpp_array_size_t"),
        (32, "m_Items", "int32_t[65535]"),
    ]
    assert model["Fixture_Int32_array"]["length"] == 262176
    assert fields(model["Il2CppObject"]) == [
        (0, "klass", "void*"),
        (8, "monitor", "void*"),
    ]
    assert fields(model["Il2CppArrayBounds"]) == [
        (0, "length", "il2cpp_array_size_t"),
        (8, "lower_bound", "int32_t"),
    ]
    assert fields(model["Cipher_Helper"]) == [
        (0, "value", "int32_t"),
        (8, "next", "struct Cipher_Helper*"),
    ]
    assert fields(model["LooksLikeArrayButIsNot"]) == [
        (0, "obj", "struct Il2CppObject"),
        (16, "count", "uint32_t"),
    ]
    assert "ExternalState" not in model
    assert model["Cipher_StaticValue"]["lengthEvidence"] == "abiDefined"
    assert all(field["offsetEvidence"] == "abiDefined"
               for name in ("Cipher_c", "Cipher_VTable", "VirtualInvokeData")
               for field in model[name]["fields"])


def test_managed_array_pointer_from_instance_fields_is_concrete():
    header = """
#include <stdint.h>
typedef uintptr_t il2cpp_array_size_t;
struct Il2CppObject { void *klass; void *monitor; };
struct Il2CppArrayBounds { il2cpp_array_size_t length; int32_t lower_bound; };
struct Fixture_Byte_array {
    struct Il2CppObject obj;
    struct Il2CppArrayBounds *bounds;
    il2cpp_array_size_t max_length;
    uint8_t m_Items[65535];
};
struct QualifiedHelper { uint32_t value; };
struct ArrayOwner_c { void *unused; };
struct ArrayOwner_Fields {
    struct Fixture_Byte_array *buffer;
    const struct QualifiedHelper **qualified;
};
struct ArrayOwner_o {
    struct ArrayOwner_c *klass;
    void *monitor;
    struct ArrayOwner_Fields fields;
};
"""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "managed-array.h"
        path.write_text(header)
        model = by_name(run(path))
    assert fields(model["ArrayOwner_o"])[-2:] == [
        (16, "buffer", "struct Fixture_Byte_array*"),
        (24, "qualified", "const struct QualifiedHelper**"),
    ]
    assert fields(model["Fixture_Byte_array"])[-2:] == [
        (24, "max_length", "il2cpp_array_size_t"),
        (32, "m_Items", "uint8_t[65535]"),
    ]
    assert fields(model["QualifiedHelper"]) == [(0, "value", "uint32_t")]


def test_runtime_interface_offset_pair_is_not_left_opaque():
    model = by_name(run(FIX / "class_metadata.h", FIX / "class_metadata_offsets.json"))
    assert any(field[1] == "interfaceOffsets" and
               field[2] == "struct Il2CppRuntimeInterfaceOffsetPair*"
               for field in fields(model["Il2CppClass_1"]))
    assert fields(model["Il2CppRuntimeInterfaceOffsetPair"]) == [
        (0, "interfaceType", "struct Il2CppClass*"),
        (8, "offset", "int32_t"),
    ]


def test_random_exact_offsets(rounds=30):
    rng = random.Random(0xC0FFEE)
    for round_no in range(rounds):
        count = rng.randint(1, 60)
        header = ["#include <stdint.h>"]
        types = {}
        expected = {}
        for i in range(count):
            name = f"T{round_no}_{i}"
            field_count = rng.randint(1, 12)
            header += [f"struct {name}_c {{ void *x; }};", f"struct {name}_Fields {{"]
            offset = 16
            fmap = {}
            exp = [(0, "klass", f"struct {name}_c *"), (8, "monitor", "void *")]
            for j in range(field_count):
                ctype, size, align = rng.choice([
                    ("uint8_t", 1, 1), ("int16_t", 2, 2),
                    ("int32_t", 4, 4), ("int64_t", 8, 8), ("float", 4, 4)])
                offset = (offset + align - 1) // align * align
                fname = f"f{j}"
                header.append(f"  {ctype} {fname};")
                fmap[fname] = offset
                exp.append((offset, fname, ctype))
                offset += size
            header += ["};", f"struct {name}_o {{ struct {name}_c *klass; void *monitor; struct {name}_Fields fields; }};"]
            types[name] = {"fields": fmap}
            expected[name + "_o"] = exp
            expected[name + "_c"] = [(0, "x", "void*")]
        with tempfile.TemporaryDirectory() as td:
            h = Path(td) / "x.h"
            j = Path(td) / "x.json"
            h.write_text("\n".join(header))
            j.write_text(json.dumps({"types": types}))
            model = by_name(run(h, j))
            assert set(model) == set(expected)
            for name, exp in expected.items():
                assert fields(model[name]) == exp, (round_no, name)


def benchmark(count=20000, fields_per_type=8):
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "large.h"
        j = Path(td) / "large.json"
        out = Path(td) / "large.i2gf"
        with h.open("w") as f:
            f.write("#include <stdint.h>\n")
            for i in range(count):
                f.write(f"struct B{i}_c {{ void *x; }};\nstruct B{i}_Fields {{\n")
                for k in range(fields_per_type):
                    f.write(f"int32_t f{k};\n")
                f.write(f"}};\nstruct B{i}_o {{ struct B{i}_c *klass; void *monitor; struct B{i}_Fields fields; }};\n")
        types = {f"B{i}": {"fields": {f"f{k}": 16 + 4*k for k in range(fields_per_type)}}
                 for i in range(count)}
        j.write_text(json.dumps({"types": types}, separators=(",", ":")))
        start = time.perf_counter()
        subprocess.run([str(CLI), str(h), str(j), str(out), "8"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        elapsed = time.perf_counter() - start
        model = decode(out)
        assert len(model["structures"]) == count * 2
        return elapsed, h.stat().st_size + j.stat().st_size, out.stat().st_size


if __name__ == "__main__":
    test_exact_json()
    test_dumpcs_matches_json()
    test_converted_super_inheritance_matches_original()
    test_natural_layout_32_and_64()
    test_schema_v2_pointer_size_and_v1_compatibility()
    test_missing_offsets_are_counted_and_skipped()
    test_empty_sidecar_does_not_enable_header_inference()
    test_partial_sidecar_never_infers_transitive_value_offsets()
    test_schema_v3_instance_size_is_preserved_as_sidecar_evidence()
    test_partial_value_uses_instance_size_without_laying_out_omitted_fields()
    test_inferred_parent_extent_uses_nested_sidecar_size()
    test_inconsistent_instance_size_is_downgraded_to_inferred_extent()
    test_schema_v2_missing_offset_categories_are_structural_and_exhaustive()
    test_unsupported_json_schema_and_early_instance_size_are_rejected()
    test_empty_value_dependency_terminates_and_header_only_reference_is_kept()
    test_nested_value_layout_survives_layout_cache_growth()
    test_empty_value_object_is_not_dropped()
    test_reference_header_collision_is_skipped_but_value_offset_zero_is_valid()
    test_static_json_offsets_do_not_override_instance_offsets()
    test_dumpcs_static_fields_are_not_used_as_instance_offsets()
    test_thread_static_only_storage_stays_opaque_and_is_reported()
    test_header_only_static_fields_match_full_header_layout()
    test_invalid_numeric_offsets_are_rejected()
    test_cumulative_sidecar_layout_budget_fails_closed()
    test_type_offsets_resource_limits_fail_closed()
    test_type_offsets_reject_ambiguous_or_invalid_json()
    test_unknown_json_properties_are_validated_and_ignored()
    test_recursive_value_alignment_is_used_for_natural_layout()
    test_recursive_value_cycle_terminates_conservatively()
    test_multidimensional_arrays_and_function_pointers_are_preserved()
    test_invalid_or_overflowing_array_dimensions_fail_closed()
    test_nested_anonymous_structs_and_unions_have_stable_structural_types()
    test_bitfields_fail_with_a_precise_parser_error()
    test_promoted_anonymous_union_is_preserved_as_a_stable_nested_type()
    test_class_vtable_and_static_fields_graph_is_emitted_selectively()
    test_managed_array_pointer_from_instance_fields_is_concrete()
    test_runtime_interface_offset_pair_is_not_left_opaque()
    test_random_exact_offsets()
    seconds, input_bytes, output_bytes = benchmark()
    print(f"native tests passed; benchmark 20,000 types: {seconds:.3f}s, "
          f"input={input_bytes/1024/1024:.1f}MiB output={output_bytes/1024/1024:.1f}MiB")
