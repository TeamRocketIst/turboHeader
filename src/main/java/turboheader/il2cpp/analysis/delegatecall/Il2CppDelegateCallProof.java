package turboheader.il2cpp.analysis.delegatecall;

import java.util.Objects;
import java.util.Optional;

import turboheader.il2cpp.analysis.ssa.SsaIdentityResolver;

final class Il2CppDelegateCallProof {
    private Il2CppDelegateCallProof() {
    }

    static <N> Resolution resolve(Callsite<N> callsite,
            SsaIdentityResolver.ValueGraph<N> graph, TypeLookup<N> types,
            SignatureLookup signatures) {
        Objects.requireNonNull(callsite, "callsite");
        Objects.requireNonNull(graph, "graph");
        Objects.requireNonNull(types, "types");
        Objects.requireNonNull(signatures, "signatures");

        N delegateObject;
        if (callsite.invokeTargetObject() == callsite.methodCodeObject() &&
                callsite.invokeTargetObject() == callsite.methodInfoObject()) {
            delegateObject = callsite.invokeTargetObject();
        }
        else {
            var identities = new SsaIdentityResolver<>(graph);
            Optional<N> targetObject = identities.resolve(callsite.invokeTargetObject());
            if (targetObject.isEmpty()) {
                return Resolution.rejected(Status.TARGET_OBJECT_NOT_EXACT);
            }
            Optional<N> methodCodeObject = identities.resolve(callsite.methodCodeObject());
            if (methodCodeObject.isEmpty()) {
                return Resolution.rejected(Status.METHOD_CODE_OBJECT_NOT_EXACT);
            }
            Optional<N> methodInfoObject = identities.resolve(callsite.methodInfoObject());
            if (methodInfoObject.isEmpty()) {
                return Resolution.rejected(Status.METHOD_INFO_OBJECT_NOT_EXACT);
            }
            if (targetObject.get() != methodCodeObject.get() ||
                    targetObject.get() != methodInfoObject.get()) {
                return Resolution.rejected(Status.DELEGATE_OBJECT_MISMATCH);
            }
            delegateObject = targetObject.get();
        }

        Optional<TypeIdentity> type = types.typeOf(delegateObject);
        if (type.isEmpty()) {
            return Resolution.rejected(Status.TYPE_NOT_EXACT);
        }
        Optional<SignatureEntry> entry = signatures.forTypeId(type.get().typeId());
        if (entry.isEmpty()) {
            return Resolution.rejected(Status.NO_CATALOG_ENTRY);
        }
        if (entry.get().typeId() != type.get().typeId() ||
                !entry.get().objectType().equals(type.get().objectType())) {
            return Resolution.rejected(Status.CATALOG_TYPE_MISMATCH);
        }

        return Resolution.proven(new Proof(callsite.callAddress(), type.get().typeId(),
                type.get().objectType(), entry.get().signature()));
    }

    enum Status {
        PROVEN,
        TARGET_OBJECT_NOT_EXACT,
        METHOD_CODE_OBJECT_NOT_EXACT,
        METHOD_INFO_OBJECT_NOT_EXACT,
        DELEGATE_OBJECT_MISMATCH,
        TYPE_NOT_EXACT,
        NO_CATALOG_ENTRY,
        CATALOG_TYPE_MISMATCH
    }

    record Callsite<N>(long callAddress, N invokeTargetObject,
            N methodCodeObject, N methodInfoObject) {
        Callsite {
            Objects.requireNonNull(invokeTargetObject, "invokeTargetObject");
            Objects.requireNonNull(methodCodeObject, "methodCodeObject");
            Objects.requireNonNull(methodInfoObject, "methodInfoObject");
        }
    }

    record TypeIdentity(int typeId, String objectType) {
        TypeIdentity {
            if (typeId < 0 || objectType == null || objectType.isBlank()) {
                throw new IllegalArgumentException("invalid delegate type identity");
            }
        }
    }

    record SignatureEntry(int typeId, String objectType, String signature) {
        SignatureEntry {
            if (typeId < 0 || objectType == null || objectType.isBlank() ||
                    signature == null || signature.isBlank()) {
                throw new IllegalArgumentException("invalid delegate signature entry");
            }
        }
    }

    record Proof(long callAddress, int typeId, String objectType, String signature) {
        Proof {
            if (typeId < 0 || objectType == null || objectType.isBlank() ||
                    signature == null || signature.isBlank()) {
                throw new IllegalArgumentException("invalid delegate-call proof");
            }
        }
    }

    record Resolution(Status status, Optional<Proof> proof) {
        Resolution {
            Objects.requireNonNull(status, "status");
            Objects.requireNonNull(proof, "proof");
            if ((status == Status.PROVEN) != proof.isPresent()) {
                throw new IllegalArgumentException("proof does not match resolution status");
            }
        }

        static Resolution proven(Proof proof) {
            return new Resolution(Status.PROVEN, Optional.of(proof));
        }

        static Resolution rejected(Status status) {
            if (status == Status.PROVEN) {
                throw new IllegalArgumentException("proven status requires a proof");
            }
            return new Resolution(status, Optional.empty());
        }
    }

    @FunctionalInterface
    interface TypeLookup<N> {
        Optional<TypeIdentity> typeOf(N value);
    }

    @FunctionalInterface
    interface SignatureLookup {
        Optional<SignatureEntry> forTypeId(int typeId);
    }
}
