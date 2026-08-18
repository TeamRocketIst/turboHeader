package turboheader.il2cpp;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.UnknownContextException;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/**
 * Names compiler-facing IL2CPP helpers from exported runtime entry points.
 *
 * <p>The exported symbol is the trusted identity. Bounded call/thunk relationships may carry that
 * identity to an internal implementation or a compiler proxy. A candidate that matches multiple
 * helper families is rejected.</p>
 */
public final class Il2CppExportedHelperAnalyzer {
    private static final int MAX_UNDEFINED_WRAPPER_INSTRUCTIONS = 16;

    private static final List<HelperDefinition> DEFINITIONS = List.of(
            new HelperDefinition(Il2CppHelperKind.OBJECT_NEW, "il2cpp_object_new",
                    TransferPreference.CALL, Relation.ANCHOR_ONLY,
                    "Il2CppObject*", List.of(
                            new Parameter("klass", "Il2CppClass*"))),
            new HelperDefinition(Il2CppHelperKind.ARRAY_NEW, "il2cpp_array_new_specific",
                    TransferPreference.JUMP, Relation.DIRECT_TAIL_TO_ANCHOR,
                    "Il2CppArray*", List.of(
                            new Parameter("arrayClass", "Il2CppClass*"),
                            new Parameter("length", "il2cpp_array_size_t"))),
            new HelperDefinition(Il2CppHelperKind.CLASS_INIT, "il2cpp_runtime_class_init",
                    TransferPreference.JUMP, Relation.ANCHOR_ONLY,
                    "void", List.of(
                            new Parameter("klass", "Il2CppClass*"))),
            new HelperDefinition(Il2CppHelperKind.GC_WRITE_BARRIER,
                    "il2cpp_gc_wbarrier_set_field", TransferPreference.JUMP,
                    Relation.DIRECT_TAIL_FROM_ANCHOR, "void", List.of(
                            new Parameter("target", "void**"),
                            new Parameter("value", "void*"))));

    private final Program program;
    private final List<Function> selectedFunctions;
    private final TaskMonitor monitor;
    private final GhidraHelperFunctionNamer namer = new GhidraHelperFunctionNamer();
    private final GhidraMethodImporter typeResolver;

    public Il2CppExportedHelperAnalyzer(Program program, List<Function> selectedFunctions,
            TaskMonitor taskMonitor) {
        this.program = program;
        this.selectedFunctions = List.copyOf(selectedFunctions);
        this.monitor = taskMonitor == null ? TaskMonitor.DUMMY : taskMonitor;
        this.typeResolver = new GhidraMethodImporter(program, this.monitor);
    }

    public AnalysisStats analyze() throws Exception {
        long started = System.nanoTime();
        Map<Il2CppHelperKind, ResolvedHelper> resolved = resolveExports();
        Set<Function> candidates = collectCompilerCallees();
        Map<Function, EnumSet<Il2CppHelperKind>> votes = classify(candidates, resolved);

        Map<Function, Il2CppHelperKind> proven = new LinkedHashMap<>();
        Set<Function> conflictingAnchors = new HashSet<>();
        int ambiguous = 0;
        for (ResolvedHelper helper : resolved.values()) {
            Function anchor = helper.anchor();
            if (conflictingAnchors.contains(anchor)) {
                continue;
            }
            Il2CppHelperKind kind = helper.definition().kind();
            Il2CppHelperKind previous = proven.putIfAbsent(anchor, kind);
            if (previous != null && previous != kind) {
                proven.remove(anchor);
                conflictingAnchors.add(anchor);
                ambiguous++;
            }
        }

        for (var entry : votes.entrySet()) {
            if (conflictingAnchors.contains(entry.getKey())) {
                continue;
            }
            if (entry.getValue().size() != 1) {
                ambiguous++;
                continue;
            }
            Il2CppHelperKind kind = entry.getValue().iterator().next();
            Il2CppHelperKind previous = proven.putIfAbsent(entry.getKey(), kind);
            if (previous != null && previous != kind) {
                proven.remove(entry.getKey());
                ambiguous++;
            }
        }

        int renamed = 0;
        int alreadyNamed = 0;
        int preserved = 0;
        int typed = 0;
        Map<Il2CppHelperKind, Integer> provenByKind = new EnumMap<>(Il2CppHelperKind.class);
        int transaction = program.startTransaction("TurboHeader IL2CPP helper identities");
        boolean commit = false;
        try {
            List<Map.Entry<Function, Il2CppHelperKind>> ordered =
                    new ArrayList<>(proven.entrySet());
            ordered.sort(Map.Entry.comparingByKey(
                    Comparator.comparing(Function::getEntryPoint)));
            for (var entry : ordered) {
                monitor.checkCancelled();
                Function function = entry.getKey();
                Il2CppHelperKind kind = entry.getValue();
                HelperDefinition definition = definition(kind);
                switch (namer.rename(function, kind)) {
                    case RENAMED -> renamed++;
                    case ALREADY_NAMED -> alreadyNamed++;
                    case PRESERVED -> {
                        preserved++;
                        continue;
                    }
                }
                applySignature(function, definition);
                typed++;
                provenByKind.merge(kind, 1, Integer::sum);
            }
            commit = true;
        }
        finally {
            program.endTransaction(transaction, commit);
        }

        Map<Il2CppHelperKind, Address> anchors = new EnumMap<>(Il2CppHelperKind.class);
        for (var entry : resolved.entrySet()) {
            anchors.put(entry.getKey(), entry.getValue().anchor().getEntryPoint());
        }
        return new AnalysisStats(selectedFunctions.size(), resolved.size(), candidates.size(),
                proven.size(), ambiguous, renamed, alreadyNamed, preserved, typed,
                Map.copyOf(anchors), Map.copyOf(provenByKind),
                System.nanoTime() - started);
    }

    private Map<Il2CppHelperKind, ResolvedHelper> resolveExports() throws Exception {
        Map<Il2CppHelperKind, ResolvedHelper> result =
                new EnumMap<>(Il2CppHelperKind.class);
        for (HelperDefinition definition : DEFINITIONS) {
            monitor.checkCancelled();
            Function exported = findExport(definition.exportedName());
            if (exported == null) {
                continue;
            }
            Function anchor = canonicalThunk(exported);
            if (anchor.equals(exported)) {
                Function transferred = preferredTransfer(exported, definition.preference());
                if (transferred != null) {
                    anchor = canonicalThunk(transferred);
                }
            }
            if (!anchor.equals(exported)) {
                result.put(definition.kind(), new ResolvedHelper(definition, exported, anchor));
            }
        }
        return result;
    }

    private Function findExport(String name) {
        List<Function> matches = new ArrayList<>();
        var symbols = program.getSymbolTable().getSymbols(name);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            Function function = program.getFunctionManager().getFunctionAt(symbol.getAddress());
            if (function != null && name.equals(function.getName()) &&
                    isExecutableMemoryFunction(function)) {
                matches.add(function);
            }
        }
        matches.sort(Comparator
                .comparing((Function function) -> function.getThunkedFunction(false) != null)
                .thenComparing(Function::getEntryPoint));
        return matches.isEmpty() ? null : matches.get(0);
    }

    private Function preferredTransfer(Function function, TransferPreference preference) {
        List<Transfer> transfers = directTransfers(function);
        return transfers.stream()
                .filter(transfer -> transfer.call() == (preference == TransferPreference.CALL))
                .map(Transfer::target)
                .findFirst()
                .orElseGet(() -> transfers.isEmpty() ? null : transfers.get(0).target());
    }

    private Set<Function> collectCompilerCallees() throws Exception {
        Set<Long> managed = Il2CppProgramFacts.readManagedMethods(program);
        Set<Function> result = new LinkedHashSet<>();
        Address imageBase = program.getImageBase();
        for (Function selected : selectedFunctions) {
            monitor.checkCancelled();
            for (Function callee : selected.getCalledFunctions(monitor)) {
                Function canonical = canonicalThunk(callee);
                if (!isExecutableMemoryFunction(canonical)) {
                    continue;
                }
                if (!managed.contains(canonical.getEntryPoint().subtract(imageBase))) {
                    result.add(canonical);
                }
            }
        }
        return Set.copyOf(result);
    }

    private Map<Function, EnumSet<Il2CppHelperKind>> classify(Set<Function> candidates,
            Map<Il2CppHelperKind, ResolvedHelper> resolved) throws Exception {
        Map<Function, EnumSet<Il2CppHelperKind>> result = new HashMap<>();
        for (Function candidate : candidates) {
            monitor.checkCancelled();
            EnumSet<Il2CppHelperKind> kinds = EnumSet.noneOf(Il2CppHelperKind.class);
            for (ResolvedHelper helper : resolved.values()) {
                Function anchor = helper.anchor();
                boolean matches = candidate.equals(anchor);
                if (!matches) {
                    matches = switch (helper.definition().relation()) {
                        case ANCHOR_ONLY -> false;
                        case DIRECT_TAIL_TO_ANCHOR ->
                                isDirectTailForwarder(candidate, anchor);
                        case DIRECT_TAIL_FROM_ANCHOR ->
                                isDirectTailForwarder(anchor, candidate);
                    };
                }
                if (matches) {
                    kinds.add(helper.definition().kind());
                }
            }
            if (!kinds.isEmpty()) {
                result.put(candidate, kinds);
            }
        }
        return result;
    }

    private boolean isDirectTailForwarder(Function function, Function expected) {
        List<Transfer> transfers = directTransfers(function);
        Transfer transfer = transfers.size() == 1 ? transfers.get(0) : null;
        return Il2CppHelperProofPolicy.provesDirectTailForwarder(
                instructionCount(function), transfers.size(),
                transfer != null && transfer.target().equals(expected),
                transfer != null && transfer.terminal());
    }

    private int instructionCount(Function function) {
        int count = 0;
        var instructions = program.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            instructions.next();
            count++;
            if (count > Il2CppHelperProofPolicy.MAX_FORWARDER_INSTRUCTIONS) {
                return count;
            }
        }
        if (count != 0) {
            return count;
        }

        PseudoDisassembler decoder = new PseudoDisassembler(program);
        Set<Address> visited = new HashSet<>();
        Address address = function.getEntryPoint();
        while (address != null && visited.add(address) &&
                count <= Il2CppHelperProofPolicy.MAX_FORWARDER_INSTRUCTIONS) {
            try {
                Instruction instruction = decoder.disassemble(address);
                count++;
                address = instruction.getFallThrough();
            }
            catch (InsufficientBytesException | UnknownInstructionException |
                    UnknownContextException ignored) {
                return 0;
            }
        }
        return count;
    }

    private List<Transfer> directTransfers(Function function) {
        if (!isExecutableMemoryFunction(function)) {
            return List.of();
        }
        Map<Address, Transfer> result = new LinkedHashMap<>();
        Function thunked = function.getThunkedFunction(false);
        if (thunked != null) {
            Function canonical = canonicalThunk(thunked);
            if (isExecutableMemoryFunction(canonical)) {
                result.put(canonical.getEntryPoint(), new Transfer(canonical, false, true));
            }
        }

        var instructions = program.getListing().getInstructions(function.getBody(), true);
        boolean hasDefinedInstructions = false;
        while (instructions.hasNext()) {
            hasDefinedInstructions = true;
            collectTransfers(instructions.next(), result);
        }
        if (!hasDefinedInstructions) {
            collectUndefinedWrapperTransfers(function, result);
        }
        return List.copyOf(result.values());
    }

    private void collectUndefinedWrapperTransfers(Function function,
            Map<Address, Transfer> result) {
        PseudoDisassembler decoder = new PseudoDisassembler(program);
        Address address = function.getEntryPoint();
        for (int count = 0;
                count < MAX_UNDEFINED_WRAPPER_INSTRUCTIONS && address != null;
                count++) {
            try {
                Instruction instruction = decoder.disassemble(address);
                collectTransfers(instruction, result);
                address = instruction.getFallThrough();
            }
            catch (InsufficientBytesException | UnknownInstructionException |
                    UnknownContextException ignored) {
                return;
            }
        }
    }

    private void collectTransfers(Instruction instruction, Map<Address, Transfer> result) {
        boolean call = instruction.getFlowType().isCall();
        if (!call && !instruction.getFlowType().isJump()) {
            return;
        }
        for (Address destination : instruction.getFlows()) {
            Function target = program.getFunctionManager().getFunctionAt(destination);
            if (target == null) {
                continue;
            }
            Function canonical = canonicalThunk(target);
            if (!isExecutableMemoryFunction(canonical)) {
                continue;
            }
            result.putIfAbsent(canonical.getEntryPoint(), new Transfer(
                    canonical, call, instruction.getFallThrough() == null));
        }
    }

    private boolean isExecutableMemoryFunction(Function function) {
        Address entry = function.getEntryPoint();
        if (!entry.getAddressSpace().equals(program.getImageBase().getAddressSpace())) {
            return false;
        }
        var block = program.getMemory().getBlock(entry);
        return block != null && block.isExecute();
    }

    private Function canonicalThunk(Function function) {
        Function current = function;
        Set<Address> visited = new HashSet<>();
        while (visited.add(current.getEntryPoint())) {
            Function next = current.getThunkedFunction(false);
            if (next == null) {
                return current;
            }
            current = next;
        }
        return current;
    }

    private void applySignature(Function function, HelperDefinition definition) {
        String name = Il2CppHelperNames.mappedName(
                definition.kind(), function.getEntryPoint().getOffset());
        FunctionDefinitionDataType signature = new FunctionDefinitionDataType(
                GhidraMethodImporter.SIGNATURES, name, program.getDataTypeManager());
        signature.setReturnType(typeResolver.resolveType(definition.returnType(), false));
        List<ParameterDefinition> arguments = new ArrayList<>();
        for (Parameter parameter : definition.parameters()) {
            arguments.add(new ParameterDefinitionImpl(parameter.name(),
                    typeResolver.resolveType(parameter.type(), true), null));
        }
        signature.setArguments(arguments.toArray(ParameterDefinition[]::new));
        var convention = program.getCompilerSpec().getDefaultCallingConvention();
        if (convention != null) {
            try {
                signature.setCallingConvention(convention.getName());
            }
            catch (Exception e) {
                throw new IllegalStateException("Could not set helper calling convention", e);
            }
        }

        ApplyFunctionSignatureCmd command = new ApplyFunctionSignatureCmd(
                function.getEntryPoint(), signature, SourceType.ANALYSIS, false, false,
                DataTypeConflictHandler.REPLACE_HANDLER, FunctionRenameOption.NO_CHANGE);
        if (!command.applyTo(program, monitor)) {
            throw new IllegalStateException("Could not type " + name + ": " +
                    command.getStatusMsg());
        }
    }

    private static HelperDefinition definition(Il2CppHelperKind kind) {
        return DEFINITIONS.stream()
                .filter(definition -> definition.kind() == kind)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "No exported-helper definition for " + kind));
    }

    private enum TransferPreference {
        CALL,
        JUMP
    }

    private enum Relation {
        ANCHOR_ONLY,
        DIRECT_TAIL_TO_ANCHOR,
        DIRECT_TAIL_FROM_ANCHOR
    }

    private record Parameter(String name, String type) {
    }

    private record HelperDefinition(Il2CppHelperKind kind, String exportedName,
            TransferPreference preference, Relation relation, String returnType,
            List<Parameter> parameters) {
    }

    private record ResolvedHelper(HelperDefinition definition, Function exported,
            Function anchor) {
    }

    private record Transfer(Function target, boolean call, boolean terminal) {
    }

    public record AnalysisStats(int selectedFunctions, int resolvedExports,
            int compilerCandidates, int provenHelpers, int ambiguousCandidates,
            int renamed, int alreadyNamed, int preserved, int typed,
            Map<Il2CppHelperKind, Address> anchors,
            Map<Il2CppHelperKind, Integer> provenByKind, long elapsedNanos) {
        public double elapsedSeconds() {
            return elapsedNanos / 1_000_000_000.0;
        }
    }
}
