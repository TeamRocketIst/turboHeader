package turboheader.il2cpp.analysis;

import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

final class Il2CppInterfaceCallProof {
    private Il2CppInterfaceCallProof() {
    }

    static <N> Resolution resolve(Callsite<N> callsite,
            ExactSsaValueResolver.ValueGraph<N> graph, DispatchLookup lookup) {
        Objects.requireNonNull(callsite, "callsite");
        Objects.requireNonNull(graph, "graph");
        Objects.requireNonNull(lookup, "lookup");

        var origins = new ExactSsaValueResolver<>(graph);
        var receiver = origins.resolve(callsite.receiver());
        if (receiver.kind() != ExactSsaValueResolver.Kind.EXACT_ALLOCATION) {
            return Resolution.rejected(Status.RECEIVER_NOT_EXACT_ALLOCATION);
        }

        var interfaceType = origins.resolve(callsite.interfaceType());
        if (interfaceType.kind() != ExactSsaValueResolver.Kind.EXACT_TYPE) {
            return Resolution.rejected(Status.INTERFACE_NOT_EXACT_TYPE);
        }

        var slot = origins.resolve(callsite.slot());
        if (slot.kind() != ExactSsaValueResolver.Kind.EXACT_CONSTANT) {
            return Resolution.rejected(Status.SLOT_NOT_CONSTANT);
        }
        if (slot.value() < 0 || slot.value() > Integer.MAX_VALUE) {
            return Resolution.rejected(Status.SLOT_OUT_OF_RANGE);
        }

        int receiverTypeId = (int) receiver.value();
        int interfaceTypeId = (int) interfaceType.value();
        int interfaceSlot = (int) slot.value();
        OptionalLong target = lookup.methodAddress(
                receiverTypeId, interfaceTypeId, interfaceSlot);
        if (target.isEmpty()) {
            return Resolution.rejected(Status.NO_CATALOG_ENTRY);
        }
        if (target.getAsLong() == 0) {
            return Resolution.rejected(Status.INVALID_TARGET);
        }

        return Resolution.proven(new Proof(callsite.indirectCallAddress(), target.getAsLong(),
                receiverTypeId, interfaceTypeId, interfaceSlot));
    }

    enum Status {
        PROVEN,
        RECEIVER_NOT_EXACT_ALLOCATION,
        INTERFACE_NOT_EXACT_TYPE,
        SLOT_NOT_CONSTANT,
        SLOT_OUT_OF_RANGE,
        NO_CATALOG_ENTRY,
        INVALID_TARGET
    }

    record Callsite<N>(long indirectCallAddress, N receiver, N interfaceType, N slot) {
        Callsite {
            Objects.requireNonNull(receiver, "receiver");
            Objects.requireNonNull(interfaceType, "interfaceType");
            Objects.requireNonNull(slot, "slot");
        }
    }

    record Proof(long indirectCallAddress, long targetAddress, int receiverTypeId,
            int interfaceTypeId, int interfaceSlot) {
        Proof {
            if (targetAddress == 0 || receiverTypeId < 0 || interfaceTypeId < 0 ||
                    interfaceSlot < 0) {
                throw new IllegalArgumentException("invalid interface-call proof");
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

    interface DispatchLookup {
        OptionalLong methodAddress(int receiverTypeId, int interfaceTypeId, int interfaceSlot);
    }
}
