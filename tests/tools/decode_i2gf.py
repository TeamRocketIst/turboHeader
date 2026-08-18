#!/usr/bin/env python3
import json
import struct
import sys
from pathlib import Path


def decode(path: Path):
    data = memoryview(path.read_bytes())
    pos = 0

    def u32():
        nonlocal pos
        if pos + 4 > len(data):
            raise ValueError("truncated u32")
        value = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        return value

    def text():
        nonlocal pos
        n = u32()
        if pos + n > len(data):
            raise ValueError("truncated string")
        value = bytes(data[pos:pos+n]).decode("utf-8")
        pos += n
        return value

    if u32() != 0x46473249:
        raise ValueError("bad magic")
    version = u32()
    if version not in (1, 2, 3):
        raise ValueError("bad version")
    pointer_size = u32()
    count = u32()
    missing = u32()
    if version >= 2:
        reason_values = [u32() for _ in range(5)]
        reason_names = ["openGenericDefinition", "concreteInstanceAbsent",
                        "unresolvedGenericParent", "objectHeaderOffset", "unsupportedLayout"]
        missing_reasons = dict(zip(reason_names, reason_values))
        missing_reasons["legacyUnclassified"] = 0
        if sum(reason_values) != missing:
            raise ValueError("missing-offset reason total mismatch")
    else:
        missing_reasons = {
            "openGenericDefinition": 0, "concreteInstanceAbsent": 0,
            "unresolvedGenericParent": 0, "objectHeaderOffset": 0,
            "unsupportedLayout": 0, "legacyUnclassified": missing,
        }
    source_names = ["legacyUnknown", "headerOnly", "typeOffsetsJson", "dumpCs"]
    evidence_names = ["legacyUnknown", "sidecarCopied", "headerInferred", "abiDefined"]
    if version == 3:
        source_value = u32()
        if source_value >= len(source_names):
            raise ValueError("bad offset source")
        offset_source = source_names[source_value]
        offset_schema_version = u32()
    else:
        offset_source = source_names[0]
        offset_schema_version = 0
    structures = []
    for _ in range(count):
        name = text()
        length = u32()
        if version == 3:
            length_evidence_value = u32()
            if length_evidence_value >= len(evidence_names):
                raise ValueError("bad structure length evidence")
            length_evidence = evidence_names[length_evidence_value]
        else:
            length_evidence = evidence_names[0]
        fields = []
        for _ in range(u32()):
            offset = u32()
            if version == 3:
                evidence_value = u32()
                if evidence_value >= len(evidence_names):
                    raise ValueError("bad field offset evidence")
                evidence = evidence_names[evidence_value]
            else:
                evidence = evidence_names[0]
            fields.append({"offset": offset, "name": text(), "type": text(),
                           "offsetEvidence": evidence})
        structures.append({"name": name, "length": length,
                           "lengthEvidence": length_evidence, "fields": fields})
    if pos != len(data):
        raise ValueError(f"trailing bytes: {len(data)-pos}")
    return {"pointerSize": pointer_size, "missingOffsets": missing,
            "missingOffsetReasons": missing_reasons, "offsetSource": offset_source,
            "offsetSchemaVersion": offset_schema_version, "structures": structures}


if __name__ == "__main__":
    model = decode(Path(sys.argv[1]))
    json.dump(model, sys.stdout, indent=2)
    print()
