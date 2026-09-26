package turboheader.il2cpp.analysis.interfacecall;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.OptionalInt;
import java.util.NavigableMap;
import java.util.Set;
import java.util.TreeMap;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import turboheader.il2cpp.metadata.Il2CppInterfaceDispatchCatalog;

final class GhidraPcodeInterfaceCallResolver {
    private static final int MAX_DEPENDENCY_VALUES = 128;
    private static final int MAX_ADDRESS_VALUES = 16;

    private final Address interfaceHelper;
    private final Set<Address> objectNewTargets;
    private final NavigableMap<Long, Integer> typeIdsByAddress;
    private final int pointerSize;
    private final Il2CppInterfaceDispatchCatalog catalog;

    GhidraPcodeInterfaceCallResolver(Address interfaceHelper,
            Set<Address> objectNewTargets, int pointerSize,
            NavigableMap<Long, Integer> typeIdsByAddress,
            Il2CppInterfaceDispatchCatalog catalog) {
        this.interfaceHelper = interfaceHelper;
        if (objectNewTargets.isEmpty()) {
            throw new IllegalArgumentException("object-new targets must not be empty");
        }
        this.objectNewTargets = Set.copyOf(objectNewTargets);
        if (pointerSize < 1 || pointerSize > Long.BYTES) {
            throw new IllegalArgumentException("unsupported pointer size");
        }
        this.pointerSize = pointerSize;
        this.catalog = catalog;
        this.typeIdsByAddress = Collections.unmodifiableNavigableMap(
                new TreeMap<>(typeIdsByAddress));
    }

    Result resolve(HighFunction highFunction) {
        List<PcodeOpAST> operations = new ArrayList<>();
        Iterator<PcodeOpAST> iterator = highFunction.getPcodeOps();
        while (iterator.hasNext()) {
            operations.add(iterator.next());
        }

        List<CallResult> results = new ArrayList<>();
        int helperCalls = 0;
        int associatedCalls = 0;
        for (PcodeOpAST operation : operations) {
            if (!calls(operation, interfaceHelper)) {
                continue;
            }
            helperCalls++;
            PcodeOpAST indirectCall = matchingIndirectCall(operation, operations);
            if (indirectCall == null || operation.getNumInputs() != 4) {
                continue;
            }
            associatedCalls++;
            var callsite = new Il2CppInterfaceCallProof.Callsite<>(
                    indirectCall.getSeqnum().getTarget().getOffset(),
                    operation.getInput(1), operation.getInput(2), operation.getInput(3));
            var resolution = Il2CppInterfaceCallProof.resolve(
                    callsite, this::describe, catalog::methodAddress);
            results.add(new CallResult(
                    operation.getSeqnum().getTarget().getOffset(),
                    indirectCall.getSeqnum().getTarget().getOffset(), resolution));
        }
        return new Result(helperCalls, associatedCalls, results);
    }

    private PcodeOpAST matchingIndirectCall(PcodeOpAST helperCall,
            List<PcodeOpAST> operations) {
        Varnode helperResult = helperCall.getOutput();
        if (helperResult == null || helperCall.getNumInputs() < 2) {
            return null;
        }

        Varnode receiver = helperCall.getInput(1);
        PcodeOpAST match = null;
        for (PcodeOpAST operation : operations) {
            if (operation.getOpcode() != PcodeOp.CALLIND || operation.getNumInputs() < 3 ||
                    !after(operation, helperCall)) {
                continue;
            }
            Varnode target = operation.getInput(0);
            Varnode dispatchedReceiver = operation.getInput(1);
            Varnode methodInfo = operation.getInput(operation.getNumInputs() - 1);
            if (!dependsOn(target, helperResult, true) ||
                    !dependsOn(methodInfo, helperResult, true) ||
                    !sameReceiver(receiver, dispatchedReceiver)) {
                continue;
            }
            if (match != null) {
                return null;
            }
            match = operation;
        }
        return match;
    }

    private boolean sameReceiver(Varnode first, Varnode second) {
        var resolver = new SsaIdentityResolver<Varnode>(this::describeIdentity);
        var firstRoot = resolver.resolve(first);
        var secondRoot = resolver.resolve(second);
        return firstRoot.isPresent() && secondRoot.isPresent() &&
                firstRoot.get() == secondRoot.get();
    }

    private SsaIdentityResolver.Value<Varnode> describeIdentity(Varnode value) {
        PcodeOp definition = value.getDef();
        if (definition == null) {
            return identity(SsaIdentityResolver.Operation.ROOT, List.of());
        }
        return switch (definition.getOpcode()) {
            case PcodeOp.COPY, PcodeOp.CAST ->
                identity(SsaIdentityResolver.Operation.COPY, inputs(definition));
            case PcodeOp.MULTIEQUAL ->
                identity(SsaIdentityResolver.Operation.MERGE, inputs(definition));
            default -> identity(SsaIdentityResolver.Operation.ROOT, List.of());
        };
    }

    private ExactSsaValueResolver.Value<Varnode> describe(Varnode value) {
        OptionalInt metadataType = metadataTypeValue(value);
        if (metadataType.isPresent()) {
            return exact(ExactSsaValueResolver.Operation.EXACT_TYPE,
                    metadataType.getAsInt());
        }
        if (value.isConstant()) {
            return exact(ExactSsaValueResolver.Operation.EXACT_CONSTANT,
                    value.getOffset());
        }

        PcodeOp definition = value.getDef();
        if (definition == null) {
            return unknown();
        }
        return switch (definition.getOpcode()) {
            case PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT ->
                operation(ExactSsaValueResolver.Operation.COPY, definition);
            case PcodeOp.MULTIEQUAL ->
                operation(ExactSsaValueResolver.Operation.MERGE, definition);
            case PcodeOp.LOAD -> typeLoad(definition);
            case PcodeOp.CALL -> allocation(definition);
            default -> unknown();
        };
    }

    private ExactSsaValueResolver.Value<Varnode> typeLoad(PcodeOp operation) {
        if (operation.getNumInputs() != 2) {
            return unknown();
        }
        var origin = new ExactSsaValueResolver<Varnode>(
                this::describeMetadataAddress).resolve(operation.getInput(1));
        return origin.kind() == ExactSsaValueResolver.Kind.EXACT_TYPE
                ? exact(ExactSsaValueResolver.Operation.EXACT_TYPE, origin.value())
                : unknown();
    }

    private ExactSsaValueResolver.Value<Varnode> allocation(PcodeOp operation) {
        if (!callsAny(operation, objectNewTargets) || operation.getNumInputs() != 2) {
            return unknown();
        }
        return new ExactSsaValueResolver.Value<>(
                ExactSsaValueResolver.Operation.ALLOCATION, 0,
                List.of(operation.getInput(1)));
    }

    private ExactSsaValueResolver.Value<Varnode> describeMetadataAddress(Varnode value) {
        if (value.isConstant() || value.getAddress().isMemoryAddress()) {
            Integer typeId = typeIdsByAddress.get(value.getOffset());
            return typeId == null
                    ? unknown()
                    : exact(ExactSsaValueResolver.Operation.EXACT_TYPE, typeId);
        }
        PcodeOp definition = value.getDef();
        if (definition == null) {
            return unknown();
        }
        if (isTransparent(definition.getOpcode()) && definition.getNumInputs() == 1) {
            return operation(ExactSsaValueResolver.Operation.COPY, definition);
        }
        if (definition.getOpcode() == PcodeOp.MULTIEQUAL) {
            return operation(ExactSsaValueResolver.Operation.MERGE, definition);
        }
        return unknown();
    }

    private OptionalInt metadataTypeValue(Varnode value) {
        TypeCoverage coverage = metadataCoverage(value,
                Collections.newSetFromMap(new IdentityHashMap<>()));
        if (coverage == null || coverage.bytes() != completePointerMask()) {
            return OptionalInt.empty();
        }
        return OptionalInt.of(coverage.typeId());
    }

    private TypeCoverage metadataCoverage(Varnode value, Set<Varnode> visited) {
        if (value == null || visited.size() >= MAX_ADDRESS_VALUES || !visited.add(value)) {
            return null;
        }
        if (value.getAddress().isMemoryAddress()) {
            var entry = typeIdsByAddress.floorEntry(value.getOffset());
            if (entry == null) {
                return null;
            }
            long delta = value.getOffset() - entry.getKey();
            if (delta < 0 || delta >= pointerSize || value.getSize() < 1 ||
                    value.getSize() > pointerSize - delta) {
                return null;
            }
            long bytes = ((1L << value.getSize()) - 1) << delta;
            return new TypeCoverage(entry.getKey(), entry.getValue(), bytes);
        }

        PcodeOp definition = value.getDef();
        if (definition == null) {
            return null;
        }
        if (isTransparent(definition.getOpcode()) && definition.getNumInputs() == 1) {
            return metadataCoverage(definition.getInput(0), visited);
        }
        if (definition.getOpcode() != PcodeOp.PIECE || definition.getNumInputs() != 2) {
            return null;
        }
        TypeCoverage first = metadataCoverage(definition.getInput(0), visited);
        TypeCoverage second = metadataCoverage(definition.getInput(1), visited);
        if (first == null || second == null || first.slotAddress() != second.slotAddress() ||
                first.typeId() != second.typeId()) {
            return null;
        }
        return new TypeCoverage(first.slotAddress(), first.typeId(),
                first.bytes() | second.bytes());
    }

    private long completePointerMask() {
        return (1L << pointerSize) - 1;
    }

    private boolean dependsOn(Varnode value, Varnode source, boolean allowPointerOps) {
        var pending = new ArrayDeque<Varnode>();
        Set<Varnode> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        pending.add(value);
        while (!pending.isEmpty() && visited.size() < MAX_DEPENDENCY_VALUES) {
            Varnode current = pending.removeLast();
            if (current == source) {
                return true;
            }
            if (!visited.add(current)) {
                continue;
            }
            PcodeOp definition = current.getDef();
            if (definition == null || !follows(definition.getOpcode(), allowPointerOps)) {
                continue;
            }
            int firstInput = definition.getOpcode() == PcodeOp.LOAD ? 1 : 0;
            for (int index = firstInput; index < definition.getNumInputs(); index++) {
                Varnode input = definition.getInput(index);
                if (input != null && !visited.contains(input)) {
                    pending.add(input);
                }
            }
        }
        return false;
    }

    private boolean calls(PcodeOp operation, Address expected) {
        if (operation.getOpcode() != PcodeOp.CALL || operation.getNumInputs() == 0) {
            return false;
        }
        Address target = operation.getInput(0).getAddress();
        return target != null && target.equals(expected);
    }

    private boolean callsAny(PcodeOp operation, Set<Address> expected) {
        if (operation.getOpcode() != PcodeOp.CALL || operation.getNumInputs() == 0) {
            return false;
        }
        Address target = operation.getInput(0).getAddress();
        return target != null && expected.contains(target);
    }

    private boolean after(PcodeOp later, PcodeOp earlier) {
        long laterAddress = later.getSeqnum().getTarget().getOffset();
        long earlierAddress = earlier.getSeqnum().getTarget().getOffset();
        return Long.compareUnsigned(laterAddress, earlierAddress) > 0;
    }

    private boolean follows(int opcode, boolean allowPointerOps) {
        if (isTransparent(opcode) || opcode == PcodeOp.MULTIEQUAL) {
            return true;
        }
        return allowPointerOps && switch (opcode) {
            case PcodeOp.LOAD, PcodeOp.PTRADD, PcodeOp.PTRSUB,
                    PcodeOp.INT_ADD, PcodeOp.SUBPIECE -> true;
            default -> false;
        };
    }

    private boolean isTransparent(int opcode) {
        return opcode == PcodeOp.COPY || opcode == PcodeOp.CAST ||
                opcode == PcodeOp.INT_ZEXT || opcode == PcodeOp.INT_SEXT;
    }

    private ExactSsaValueResolver.Value<Varnode> operation(
            ExactSsaValueResolver.Operation operation, PcodeOp pcode) {
        return new ExactSsaValueResolver.Value<>(operation, 0, inputs(pcode));
    }

    private SsaIdentityResolver.Value<Varnode> identity(
            SsaIdentityResolver.Operation operation, List<Varnode> inputs) {
        return new SsaIdentityResolver.Value<>(operation, inputs);
    }

    private List<Varnode> inputs(PcodeOp pcode) {
        List<Varnode> result = new ArrayList<>(pcode.getNumInputs());
        for (int index = 0; index < pcode.getNumInputs(); index++) {
            result.add(pcode.getInput(index));
        }
        return result;
    }

    private ExactSsaValueResolver.Value<Varnode> exact(
            ExactSsaValueResolver.Operation operation, long value) {
        return new ExactSsaValueResolver.Value<>(operation, value, List.of());
    }

    private ExactSsaValueResolver.Value<Varnode> unknown() {
        return exact(ExactSsaValueResolver.Operation.UNKNOWN, 0);
    }

    private record TypeCoverage(long slotAddress, int typeId, long bytes) {
    }

    record CallResult(long helperCallAddress, long indirectCallAddress,
            Il2CppInterfaceCallProof.Resolution resolution) {
    }

    record Result(int helperCalls, int associatedCalls, List<CallResult> calls) {
        Result {
            calls = List.copyOf(calls);
            if (helperCalls < 0 || associatedCalls < 0 ||
                    associatedCalls > helperCalls || calls.size() != associatedCalls) {
                throw new IllegalArgumentException("invalid P-code proof statistics");
            }
        }
    }
}
