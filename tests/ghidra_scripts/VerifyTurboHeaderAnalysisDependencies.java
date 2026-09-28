// @category Test

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import turboheader.il2cpp.Il2CppExportPlanner;
import turboheader.il2cpp.analysis.delegatecall.Il2CppDelegateCallAnalyzer;
import turboheader.il2cpp.analysis.delegatecall.Il2CppDelegatePrototypeCatalog;
import turboheader.il2cpp.analysis.pipeline.Il2CppExportAnalysisService;
import turboheader.il2cpp.decompile.Il2CppFunctionPreparationService;
import turboheader.il2cpp.exporting.Il2CppClassCatalog;
import turboheader.il2cpp.metadata.Il2CppDelegateSignatureCatalog;
import turboheader.il2cpp.metadata.Il2CppDelegateSignatureStore;
import turboheader.il2cpp.metadata.Il2CppSharedGenericCallCatalog;
import turboheader.il2cpp.metadata.Il2CppSharedGenericCallStore;
import turboheader.il2cpp.metadata.ScriptMethodReader;

public class VerifyTurboHeaderAnalysisDependencies extends GhidraScript {
    private static final long CALLER = 0x1000;
    private static final long PRODUCER = 0x1200;
    private static final long METHOD_INFO = 0x1800;
    private static final String PRODUCER_SIGNATURE =
            "void shared_generic_call (Il2CppObject* __this, int32_t index, " +
            "Sample_Callback_o** __result, const MethodInfo* method);";
    private static final String DELEGATE_SIGNATURE =
            "void delegate_invoke (Il2CppMethodPointer methodCode, " +
            "int32_t value, const MethodInfo* method);";

    @Override
    protected void run() throws Exception {
        verify(monitor);
        println("TurboHeader analysis dependency verification passed");
    }

    public static void verify(TaskMonitor monitor) throws Exception {
        checkFixture(monitor, false, true, false);
        checkFixture(monitor, true, false, false);
        checkFixture(monitor, true, true, false);
        checkFixture(monitor, true, true, true);
    }

    private static void checkFixture(TaskMonitor monitor, boolean metadata,
            boolean validProducer, boolean conflict) throws Exception {
        var language = DefaultLanguageService.getLanguageService()
                .getLanguage(new LanguageID("AARCH64:LE:64:v8A"));
        Object owner = new Object();
        var program = new ProgramDB("analysis-dependency", language,
                language.getDefaultCompilerSpec(), owner);
        try {
            Function caller = createFixture(program, monitor, metadata, validProducer);
            var baseline = Il2CppDelegateCallAnalyzer.analyze(program, List.of(caller),
                    Il2CppDelegatePrototypeCatalog.read(program), monitor);
            require(baseline.failedFunctions() == 0, "baseline decompiler failed");
            require(baseline.delegateCandidates() == 1, "baseline delegate shape missing");
            require(baseline.provenCalls() == 0, "untyped receiver unexpectedly proved");

            var ready = new Il2CppFunctionPreparationService.PreparedFunction(caller, caller);
            var entry = new Il2CppClassCatalog.ClassEntry("Sample.Game", "Sample.cs",
                    Path.of("fixtures", "Sample.cs"));
            var plan = new Il2CppExportPlanner.ClassPlan(entry, Path.of("Sample.cpp"),
                    List.of(caller));
            var prepared = new Il2CppFunctionPreparationService.PreparedClassPlan(
                    plan, List.of(ready));
            var preparation = new Il2CppFunctionPreparationService.PreparationResult(
                    List.of(prepared), List.of(ready), 1, 0, 0);
            var cancelled = new TaskMonitorAdapter(true);
            cancelled.cancel();
            long beforeCancellation = program.getModificationNumber();
            try {
                Il2CppExportAnalysisService.analyzeAfterPreparation(
                        program, preparation, cancelled);
                throw new AssertionError("cancelled analysis continued");
            }
            catch (CancelledException expected) {
                require(program.getModificationNumber() == beforeCancellation,
                        "cancelled analysis changed the program");
            }
            if (conflict) {
                checkConflict(program, caller, preparation, monitor);
                return;
            }
            var result = Il2CppExportAnalysisService.analyzeAfterPreparation(
                    program, preparation, monitor);
            int expected = metadata && validProducer ? 1 : 0;
            require(result.sharedGenericCalls().provenCalls() == expected,
                    "unexpected producer proof count");
            require(result.publishedSharedGenericCalls().added() == expected,
                    "producer override count differs");
            require(result.delegateCalls().failedFunctions() == 0,
                    "delegate decompiler failed");
            require(result.delegateCalls().provenCalls() == expected,
                    "delegate analysis did not consume the producer type");
            require(result.publishedDelegateCalls().added() == expected,
                    "delegate override count differs");
            if (expected == 1) {
                var proof = result.delegateCalls().proofs().getFirst();
                require(proof.callsite().equals(caller.getEntryPoint().add(13 * 4)) &&
                        proof.objectType().equals("Sample_Callback_o*") &&
                        proof.signature().equals(DELEGATE_SIGNATURE),
                        "delegate proof does not match the supplied signature");
            }
            require(result.stableModificationNumber() == program.getModificationNumber(),
                    "stable program marker differs");

            var repeated = Il2CppExportAnalysisService.analyzeAfterPreparation(
                    program, preparation, monitor);
            require(repeated.sharedGenericCalls().proofs().equals(
                    result.sharedGenericCalls().proofs()), "producer proofs changed");
            require(repeated.delegateCalls().proofs().equals(result.delegateCalls().proofs()),
                    "delegate proofs changed");
            require(repeated.publishedSharedGenericCalls().added() == 0 &&
                    repeated.publishedSharedGenericCalls().retained() == expected,
                    "producer publication was not idempotent");
            require(repeated.publishedDelegateCalls().added() == 0 &&
                    repeated.publishedDelegateCalls().retained() == expected,
                    "delegate publication was not idempotent");
        }
        finally {
            program.release(owner);
        }
    }

    private static void checkConflict(ProgramDB program, Function caller,
            Il2CppFunctionPreparationService.PreparationResult preparation,
            TaskMonitor monitor) throws Exception {
        Address producerCall = caller.getEntryPoint().add(7 * 4);
        Address delegateCall = caller.getEntryPoint().add(13 * 4);
        var existing = new FunctionDefinitionDataType("existing_prototype");
        existing.setReturnType(VoidDataType.dataType);
        int transaction = program.startTransaction("Install conflicting prototype");
        try {
            HighFunctionDBUtil.writeOverride(caller, producerCall, existing);
        }
        finally {
            program.endTransaction(transaction, true);
        }
        String original = overridePrototype(program, caller, producerCall);
        try {
            Il2CppExportAnalysisService.analyzeAfterPreparation(program, preparation, monitor);
            throw new AssertionError("conflicting producer override was overwritten");
        }
        catch (IllegalStateException expected) {
            require(expected.getMessage().startsWith("conflicting prototype override"),
                    "analysis failed for an unexpected reason");
        }
        var namespace = HighFunction.findOverrideSpace(caller);
        require(overridePrototype(program, caller, producerCall).equals(original),
                "existing producer prototype changed");
        for (var symbol : program.getSymbolTable().getSymbols(delegateCall)) {
            require(!symbol.getParentNamespace().equals(namespace),
                    "delegate override published after producer conflict");
        }
    }

    private static String overridePrototype(ProgramDB program, Function caller, Address callsite) {
        var namespace = HighFunction.findOverrideSpace(caller);
        String result = null;
        for (var symbol : program.getSymbolTable().getSymbols(callsite)) {
            if (symbol.getParentNamespace().equals(namespace)) {
                var stored = HighFunctionDBUtil.readOverride(symbol);
                require(stored != null && stored.getDataType() instanceof FunctionSignature,
                        "invalid producer override");
                require(result == null, "duplicate producer overrides");
                var signature = (FunctionSignature) stored.getDataType();
                result = symbol.getID() + ":" + signature.getPrototypeString();
            }
        }
        require(result != null, "existing producer override was lost");
        return result;
    }

    private static Function createFixture(ProgramDB program, TaskMonitor monitor,
            boolean metadata, boolean validProducer) throws Exception {
        int transaction = program.startTransaction("Create synthetic call dependency");
        boolean commit = false;
        try {
            var manager = program.getDataTypeManager();
            var category = new CategoryPath("/IL2CPP");
            for (String name : List.of("System_Delegate_o", "Sample_Callback_o")) {
                var layout = new StructureDataType(category, name, 96, manager);
                layout.replaceAtOffset(32, Undefined8DataType.dataType, 8, "invoke_impl", null);
                layout.replaceAtOffset(48, Undefined8DataType.dataType, 8, "method", null);
                layout.replaceAtOffset(72, Undefined8DataType.dataType, 8, "method_code", null);
                manager.addDataType(layout, DataTypeConflictHandler.REPLACE_HANDLER);
            }
            for (String name : List.of("Il2CppObject", "MethodInfo")) {
                manager.addDataType(new StructureDataType(category, name, 16, manager),
                        DataTypeConflictHandler.REPLACE_HANDLER);
            }
            var delegate = new ScriptMethodReader.ScriptDelegateSignature(1,
                    "Sample_Callback_o*", DELEGATE_SIGNATURE);
            var producer = new ScriptMethodReader.ScriptSharedGenericCall(
                    METHOD_INFO, PRODUCER, PRODUCER_SIGNATURE);
            var data = new ScriptMethodReader.ScriptData(List.of(), List.of(), List.of(),
                    List.of(), Optional.empty(), Optional.of(List.of(delegate)),
                    metadata ? Optional.of(List.of(producer)) : Optional.empty());
            Il2CppDelegateSignatureStore.replace(program,
                    Il2CppDelegateSignatureCatalog.fromScript(data));
            Il2CppSharedGenericCallStore.replace(program,
                    Il2CppSharedGenericCallCatalog.fromScript(data));

            var block = program.getMemory().createInitializedBlock("code",
                    address(program, CALLER), 4096, (byte) 0, monitor, false);
            block.setExecute(true);
            var assembler = Assemblers.getAssembler(program);
            assembler.assemble(address(program, PRODUCER), "ret");
            require(new CreateFunctionCmd(address(program, PRODUCER)).applyTo(program, monitor),
                    "producer creation failed");
            // The producer writes a callback pointer into the caller's stack slot.
            assembler.assemble(address(program, CALLER),
                    "sub sp,sp,#0x40", "stp x29,x30,[sp,#0x30]", "str x19,[sp,#0x28]",
                    "mov w1,#0", "add x2,sp,#0x10", "mov x8,#0x1800",
                    validProducer ? "ldr x3,[x8]" : "mov x3,#0", "bl 0x1200",
                    "ldr x19,[sp,#0x10]", "ldr x9,[x19,#32]", "ldr x0,[x19,#72]",
                    "ldr x2,[x19,#48]", "mov w1,#1", "blr x9",
                    "ldr x19,[sp,#0x28]", "ldp x29,x30,[sp,#0x30]", "add sp,sp,#0x40", "ret");
            require(new CreateFunctionCmd(address(program, CALLER)).applyTo(program, monitor),
                    "caller creation failed");
            Function caller = program.getFunctionManager().getFunctionAt(address(program, CALLER));
            caller.setName("sample_invoke", SourceType.USER_DEFINED);
            caller.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
            commit = true;
            return caller;
        }
        finally {
            program.endTransaction(transaction, commit);
        }
    }

    private static Address address(ProgramDB program, long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
