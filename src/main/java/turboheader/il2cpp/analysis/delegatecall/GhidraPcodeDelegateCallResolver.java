package turboheader.il2cpp.analysis.delegatecall;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import turboheader.il2cpp.analysis.ssa.SsaIdentityResolver;
import turboheader.il2cpp.types.GhidraTypeImporter;

final class GhidraPcodeDelegateCallResolver {
    private final Il2CppDelegateFieldLayout layout;
    private final Il2CppDelegatePrototypeCatalog catalog;

    GhidraPcodeDelegateCallResolver(Il2CppDelegateFieldLayout layout,
            Il2CppDelegatePrototypeCatalog catalog) {
        this.layout = layout;
        this.catalog = catalog;
    }

    Result resolve(HighFunction highFunction) {
        int indirectCalls = 0;
        int delegateCandidates = 0;
        int shapeRejected = 0;
        List<CallResult> results = new ArrayList<>();
        Iterator<PcodeOpAST> operations = highFunction.getPcodeOps();
        while (operations.hasNext()) {
            PcodeOpAST operation = operations.next();
            if (operation.getOpcode() != PcodeOp.CALLIND) {
                continue;
            }
            indirectCalls++;
            Optional<Varnode> targetObject = fieldObject(
                    operation.getInput(0), layout.invokeTargetOffset());
            if (targetObject.isEmpty()) {
                continue;
            }
            delegateCandidates++;
            if (operation.getNumInputs() < 3) {
                shapeRejected++;
                continue;
            }
            Optional<Varnode> methodCodeObject = fieldObject(
                    operation.getInput(1), layout.methodCodeOffset());
            Optional<Varnode> methodInfoObject = fieldObject(
                    operation.getInput(operation.getNumInputs() - 1),
                    layout.methodInfoOffset());
            if (methodCodeObject.isEmpty() || methodInfoObject.isEmpty()) {
                shapeRejected++;
                continue;
            }

            Address callAddress = operation.getSeqnum().getTarget();
            var callsite = new Il2CppDelegateCallProof.Callsite<>(callAddress.getOffset(),
                    targetObject.orElseThrow(), methodCodeObject.orElseThrow(),
                    methodInfoObject.orElseThrow());
            var resolution = Il2CppDelegateCallProof.resolve(callsite,
                    this::describeIdentity,
                    value -> typeOf(highFunction, value), this::signatureForType);
            results.add(new CallResult(callAddress, resolution));
        }
        return new Result(indirectCalls, delegateCandidates, shapeRejected, results);
    }

    private Optional<Varnode> fieldObject(Varnode value, long wantedOffset) {
        Varnode source = transparentSource(value);
        PcodeOp definition = source.getDef();
        if (definition == null || definition.getOpcode() != PcodeOp.LOAD ||
                definition.getNumInputs() != 2) {
            return Optional.empty();
        }
        Optional<AddressExpression> address = addressExpression(definition.getInput(1), 0);
        if (address.isEmpty() || address.get().offset() != wantedOffset) {
            return Optional.empty();
        }
        return Optional.of(address.get().base());
    }

    private Optional<AddressExpression> addressExpression(Varnode value, int depth) {
        if (depth > 16 || value == null || value.isConstant()) {
            return Optional.empty();
        }
        PcodeOp definition = value.getDef();
        if (definition == null) {
            return Optional.of(new AddressExpression(value, 0));
        }
        if (isTransparent(definition.getOpcode()) && definition.getNumInputs() == 1) {
            return addressExpression(definition.getInput(0), depth + 1);
        }
        if (definition.getOpcode() == PcodeOp.INT_ADD &&
                definition.getNumInputs() == 2) {
            return addConstant(definition.getInput(0), definition.getInput(1), depth);
        }
        if (definition.getOpcode() == PcodeOp.PTRSUB &&
                definition.getNumInputs() == 2 &&
                !definition.getInput(0).isConstant() &&
                definition.getInput(1).isConstant()) {
            return addConstant(definition.getInput(0), definition.getInput(1), depth);
        }
        if (definition.getOpcode() == PcodeOp.PTRADD && definition.getNumInputs() == 3 &&
                definition.getInput(1).isConstant() &&
                definition.getInput(2).isConstant()) {
            Optional<AddressExpression> base = addressExpression(
                    definition.getInput(0), depth + 1);
            if (base.isEmpty()) {
                return Optional.empty();
            }
            try {
                long scaled = Math.multiplyExact(definition.getInput(1).getOffset(),
                        definition.getInput(2).getOffset());
                return Optional.of(new AddressExpression(base.get().base(),
                        Math.addExact(base.get().offset(), scaled)));
            }
            catch (ArithmeticException e) {
                return Optional.empty();
            }
        }
        return Optional.of(new AddressExpression(value, 0));
    }

    private Optional<AddressExpression> addConstant(Varnode first, Varnode second,
            int depth) {
        Varnode base;
        long displacement;
        if (first.isConstant() == second.isConstant()) {
            return Optional.empty();
        }
        if (first.isConstant()) {
            base = second;
            displacement = first.getOffset();
        }
        else {
            base = first;
            displacement = second.getOffset();
        }
        Optional<AddressExpression> expression = addressExpression(base, depth + 1);
        if (expression.isEmpty()) {
            return Optional.empty();
        }
        try {
            return Optional.of(new AddressExpression(expression.get().base(),
                    Math.addExact(expression.get().offset(), displacement)));
        }
        catch (ArithmeticException e) {
            return Optional.empty();
        }
    }

    private Varnode transparentSource(Varnode value) {
        Varnode current = value;
        for (int depth = 0; depth < 16; depth++) {
            PcodeOp definition = current.getDef();
            if (definition == null || !isTransparent(definition.getOpcode()) ||
                    definition.getNumInputs() != 1) {
                return current;
            }
            current = definition.getInput(0);
        }
        return current;
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

    private Optional<Il2CppDelegateCallProof.TypeIdentity> typeOf(
            HighFunction highFunction, Varnode value) {
        DataType type = value.getHigh() == null
                ? parameterType(highFunction, value).orElse(null)
                : value.getHigh().getDataType();
        if (type == null) {
            return Optional.empty();
        }
        type = unwrap(type);
        if (!(type instanceof Pointer pointer)) {
            return Optional.empty();
        }
        DataType target = unwrap(pointer.getDataType());
        if (target == null || !target.getCategoryPath().equals(GhidraTypeImporter.ROOT)) {
            return Optional.empty();
        }
        String objectType = target.getName() + "*";
        return catalog.forObjectType(objectType)
                .map(prototype -> new Il2CppDelegateCallProof.TypeIdentity(
                        prototype.typeId(), objectType));
    }

    private Optional<DataType> parameterType(HighFunction highFunction, Varnode value) {
        if (value.getDef() != null) {
            return Optional.empty();
        }
        for (var parameter : highFunction.getFunction().getParameters()) {
            for (Varnode storage : parameter.getVariableStorage().getVarnodes()) {
                if (sameStorage(value, storage)) {
                    return Optional.of(parameter.getDataType());
                }
            }
        }
        var symbols = highFunction.getLocalSymbolMap();
        for (int index = 0; index < symbols.getNumParams(); index++) {
            var parameter = symbols.getParam(index);
            if (parameter == null) {
                continue;
            }
            if (sameStorage(value, parameter.getRepresentative())) {
                return Optional.of(parameter.getDataType());
            }
            for (Varnode instance : parameter.getInstances()) {
                if (sameStorage(value, instance)) {
                    return Optional.of(parameter.getDataType());
                }
            }
        }
        return Optional.empty();
    }

    private boolean sameStorage(Varnode first, Varnode second) {
        return first != null && second != null && first.getSize() == second.getSize() &&
                first.getAddress().equals(second.getAddress());
    }

    private Optional<Il2CppDelegateCallProof.SignatureEntry> signatureForType(int typeId) {
        return catalog.forTypeId(typeId)
                .map(prototype -> new Il2CppDelegateCallProof.SignatureEntry(
                        prototype.typeId(), prototype.objectType(), prototype.signature()));
    }

    private static DataType unwrap(DataType type) {
        DataType current = type;
        while (current instanceof TypeDef definition) {
            current = definition.getDataType();
        }
        return current;
    }

    private static boolean isTransparent(int opcode) {
        return opcode == PcodeOp.COPY || opcode == PcodeOp.CAST ||
                opcode == PcodeOp.INT_ZEXT || opcode == PcodeOp.INT_SEXT;
    }

    private static List<Varnode> inputs(PcodeOp operation) {
        List<Varnode> result = new ArrayList<>(operation.getNumInputs());
        for (int index = 0; index < operation.getNumInputs(); index++) {
            result.add(operation.getInput(index));
        }
        return result;
    }

    private static SsaIdentityResolver.Value<Varnode> identity(
            SsaIdentityResolver.Operation operation, List<Varnode> inputs) {
        return new SsaIdentityResolver.Value<>(operation, inputs);
    }

    private record AddressExpression(Varnode base, long offset) {
    }

    record CallResult(Address callAddress, Il2CppDelegateCallProof.Resolution resolution) {
    }

    record Result(int indirectCalls, int delegateCandidates, int shapeRejected,
            List<CallResult> calls) {
        Result {
            calls = List.copyOf(calls);
            if (indirectCalls < 0 || delegateCandidates < 0 || shapeRejected < 0 ||
                    delegateCandidates > indirectCalls ||
                    shapeRejected + calls.size() != delegateCandidates) {
                throw new IllegalArgumentException("invalid delegate P-code statistics");
            }
        }
    }
}
