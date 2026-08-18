package turboheader.il2cpp;

import java.util.List;
import java.util.Objects;

/** Immutable model emitted by the native IL2CPP parser. */
public final class TypeModel {
    private TypeModel() {
    }

    public enum OffsetSource {
        LEGACY_UNKNOWN(0),
        HEADER_ONLY(1),
        TYPE_OFFSETS_JSON(2),
        DUMP_CS(3);

        private final int wireValue;

        OffsetSource(int wireValue) {
            this.wireValue = wireValue;
        }

        int wireValue() {
            return wireValue;
        }

        static OffsetSource fromWire(int wireValue) {
            for (OffsetSource value : values()) {
                if (value.wireValue == wireValue) {
                    return value;
                }
            }
            throw new IllegalArgumentException("invalid offset source: " +
                    Integer.toUnsignedString(wireValue));
        }
    }

    public enum LayoutEvidence {
        LEGACY_UNKNOWN(0),
        SIDECAR_COPIED(1),
        HEADER_INFERRED(2),
        ABI_DEFINED(3);

        private final int wireValue;

        LayoutEvidence(int wireValue) {
            this.wireValue = wireValue;
        }

        int wireValue() {
            return wireValue;
        }

        static LayoutEvidence fromWire(int wireValue) {
            for (LayoutEvidence value : values()) {
                if (value.wireValue == wireValue) {
                    return value;
                }
            }
            throw new IllegalArgumentException("invalid layout evidence: " +
                    Integer.toUnsignedString(wireValue));
        }
    }

    public record Model(int pointerSize, int missingOffsets, List<StructDef> structures,
            MissingOffsetReasons missingOffsetReasons, OffsetSource offsetSource,
            int offsetSchemaVersion) {
        public Model(int pointerSize, int missingOffsets, List<StructDef> structures) {
            this(pointerSize, missingOffsets, structures, MissingOffsetReasons.legacy(missingOffsets),
                    OffsetSource.LEGACY_UNKNOWN, 0);
        }

        public Model(int pointerSize, int missingOffsets, List<StructDef> structures,
                MissingOffsetReasons missingOffsetReasons) {
            this(pointerSize, missingOffsets, structures, missingOffsetReasons,
                    OffsetSource.LEGACY_UNKNOWN, 0);
        }

        public Model(int pointerSize, int missingOffsets, List<StructDef> structures,
                OffsetSource offsetSource, int offsetSchemaVersion) {
            this(pointerSize, missingOffsets, structures, MissingOffsetReasons.legacy(missingOffsets),
                    offsetSource, offsetSchemaVersion);
        }

        public Model {
            if (pointerSize != 4 && pointerSize != 8) {
                throw new IllegalArgumentException("pointerSize must be 4 or 8");
            }
            if (missingOffsets < 0) {
                throw new IllegalArgumentException("missingOffsets must not be negative");
            }
            structures = List.copyOf(Objects.requireNonNull(structures, "structures"));
            Objects.requireNonNull(missingOffsetReasons, "missingOffsetReasons");
            Objects.requireNonNull(offsetSource, "offsetSource");
            if (offsetSchemaVersion < 0) {
                throw new IllegalArgumentException("offsetSchemaVersion must not be negative");
            }
            if (offsetSource == OffsetSource.LEGACY_UNKNOWN && offsetSchemaVersion != 0) {
                throw new IllegalArgumentException("legacy model has a sidecar schema version");
            }
            if (offsetSource == OffsetSource.HEADER_ONLY && offsetSchemaVersion != 0) {
                throw new IllegalArgumentException("header-only model has a sidecar schema version");
            }
            if (offsetSource == OffsetSource.DUMP_CS && offsetSchemaVersion != 0) {
                throw new IllegalArgumentException("dump.cs model has a JSON schema version");
            }
            if (offsetSource == OffsetSource.TYPE_OFFSETS_JSON && offsetSchemaVersion > 3) {
                throw new IllegalArgumentException("unsupported type_offsets.json schema version: " +
                        offsetSchemaVersion);
            }
            if (missingOffsetReasons.total() != missingOffsets) {
                throw new IllegalArgumentException("missing-offset reason total does not match missingOffsets");
            }
            for (StructDef structure : structures) {
                validateEvidence(offsetSource, offsetSchemaVersion,
                        structure.lengthEvidence(), true);
                for (FieldDef field : structure.fields()) {
                    validateEvidence(offsetSource, offsetSchemaVersion,
                            field.offsetEvidence(), false);
                }
            }
        }

        private static void validateEvidence(OffsetSource source, int schemaVersion,
                LayoutEvidence evidence, boolean structureLength) {
            if (source == OffsetSource.LEGACY_UNKNOWN &&
                    evidence != LayoutEvidence.LEGACY_UNKNOWN) {
                throw new IllegalArgumentException("legacy model contains non-legacy layout evidence");
            }
            if (source == OffsetSource.HEADER_ONLY &&
                    evidence == LayoutEvidence.SIDECAR_COPIED) {
                throw new IllegalArgumentException("header-only model contains a sidecar offset");
            }
            if (source != OffsetSource.LEGACY_UNKNOWN &&
                    evidence == LayoutEvidence.LEGACY_UNKNOWN) {
                throw new IllegalArgumentException("current model contains legacy layout evidence");
            }
            if (!structureLength &&
                    (source == OffsetSource.TYPE_OFFSETS_JSON || source == OffsetSource.DUMP_CS) &&
                    evidence == LayoutEvidence.HEADER_INFERRED) {
                throw new IllegalArgumentException("sidecar model contains an inferred layout");
            }
            if (structureLength && evidence == LayoutEvidence.SIDECAR_COPIED &&
                    (source != OffsetSource.TYPE_OFFSETS_JSON || schemaVersion < 3)) {
                throw new IllegalArgumentException(
                        "structure extent is not available from this sidecar schema");
            }
        }

        public EvidenceCounts evidenceCounts() {
            int unknown = 0;
            int copied = 0;
            int inferred = 0;
            int abi = 0;
            for (StructDef structure : structures) {
                for (FieldDef field : structure.fields()) {
                    switch (field.offsetEvidence()) {
                        case LEGACY_UNKNOWN -> unknown++;
                        case SIDECAR_COPIED -> copied++;
                        case HEADER_INFERRED -> inferred++;
                        case ABI_DEFINED -> abi++;
                    }
                }
            }
            return new EvidenceCounts(unknown, copied, inferred, abi);
        }

        public EvidenceCounts lengthEvidenceCounts() {
            int unknown = 0;
            int copied = 0;
            int inferred = 0;
            int abi = 0;
            for (StructDef structure : structures) {
                switch (structure.lengthEvidence()) {
                    case LEGACY_UNKNOWN -> unknown++;
                    case SIDECAR_COPIED -> copied++;
                    case HEADER_INFERRED -> inferred++;
                    case ABI_DEFINED -> abi++;
                }
            }
            return new EvidenceCounts(unknown, copied, inferred, abi);
        }
    }

    public record EvidenceCounts(int legacyUnknown, int sidecarCopied, int headerInferred,
            int abiDefined) {
        public int total() {
            return Math.addExact(Math.addExact(legacyUnknown, sidecarCopied),
                    Math.addExact(headerInferred, abiDefined));
        }
    }

    public record MissingOffsetReasons(int openGenericDefinition, int concreteInstanceAbsent,
            int unresolvedGenericParent, int objectHeaderOffset, int unsupportedLayout,
            int legacyUnclassified) {
        public MissingOffsetReasons {
            if (openGenericDefinition < 0 || concreteInstanceAbsent < 0 ||
                    unresolvedGenericParent < 0 || objectHeaderOffset < 0 ||
                    unsupportedLayout < 0 || legacyUnclassified < 0) {
                throw new IllegalArgumentException("missing-offset reason counts must not be negative");
            }
        }

        public int total() {
            return Math.addExact(Math.addExact(Math.addExact(openGenericDefinition,
                    concreteInstanceAbsent), Math.addExact(unresolvedGenericParent, objectHeaderOffset)),
                    Math.addExact(unsupportedLayout, legacyUnclassified));
        }

        static MissingOffsetReasons legacy(int total) {
            return new MissingOffsetReasons(0, 0, 0, 0, 0, total);
        }
    }

    public record StructDef(String name, int length, List<FieldDef> fields,
            LayoutEvidence lengthEvidence) {
        public StructDef(String name, int length, List<FieldDef> fields) {
            this(name, length, fields, LayoutEvidence.LEGACY_UNKNOWN);
        }

        public StructDef {
            Objects.requireNonNull(name, "name");
            if (name.isBlank()) {
                throw new IllegalArgumentException("blank structure name");
            }
            if (length < 1) {
                throw new IllegalArgumentException("structure length must be positive: " + name);
            }
            fields = List.copyOf(Objects.requireNonNull(fields, "fields"));
            Objects.requireNonNull(lengthEvidence, "lengthEvidence");
        }
    }

    public record FieldDef(int offset, String name, String cType, LayoutEvidence offsetEvidence) {
        public FieldDef(int offset, String name, String cType) {
            this(offset, name, cType, LayoutEvidence.LEGACY_UNKNOWN);
        }

        public FieldDef {
            if (offset < 0) {
                throw new IllegalArgumentException("negative field offset");
            }
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(cType, "cType");
            Objects.requireNonNull(offsetEvidence, "offsetEvidence");
            if (name.isBlank() || cType.isBlank()) {
                throw new IllegalArgumentException("blank field name/type");
            }
        }
    }
}
