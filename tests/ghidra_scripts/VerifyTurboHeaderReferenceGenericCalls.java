// Exercises ordinary reference returns without changing the shared callee.
// @category Test

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitorAdapter;
import turboheader.il2cpp.analysis.sharedgeneric.Il2CppSharedGenericCallAnalyzer;
import turboheader.il2cpp.analysis.sharedgeneric.Il2CppSharedGenericCallPublisher;
import turboheader.il2cpp.analysis.sharedgeneric.GenericCallContract;
import turboheader.il2cpp.metadata.GhidraMethodImporter;
import turboheader.il2cpp.metadata.Il2CppReferenceGenericCallCatalog;
import turboheader.il2cpp.metadata.ScriptMethodReader;
import turboheader.il2cpp.types.GhidraTypeImporter;

public class VerifyTurboHeaderReferenceGenericCalls extends GhidraScript {
    private static final long CALLER = 0x1000;
    private static final long TARGET = 0x1800;
    private static final long SLOT = 0x3000;
    private static final String SIGNATURE =
            "Sample_Item_o* reference_generic_call (Sample_Box_o* __this, int32_t arg1, const MethodInfo* method);";

    @Override
    protected void run() throws Exception {
        positive(0, false);
        positive(0x100000, true);
        for (String mode : List.of("null-check", "equal-join", "stable-loop", "preserved-call", "uninitialized-store",
                "float-compare", "select-unrelated", "compare-after-call")) {
            flowCase(mode, true);
        }
        for (String mode : List.of("conflicting-join", "unknown-join", "changing-loop", "volatile-call",
                "writable-got", "external-entry", "slot-store", "partial-slot-store", "select-slot",
                "select-slot-alias", "select-method-info")) {
            flowCase(mode, false);
        }
        instructionBudget();
        for (String mode : List.of("token", "clobber", "branch", "register", "missing-type",
                "opaque-type", "conflict-type", "return-abi", "parameter-abi", "non-executable", "wrong-target",
                "store", "window", "hidden-flow")) {
            negative(mode);
        }
        println("TurboHeader reference-generic proof and publication verification passed");
    }

    private void positive(long imageBase, boolean got) throws Exception {
        ProgramDB program = fixture(imageBase, got, "valid");
        try {
            Function first = function(program, CALLER);
            Function second = function(program, CALLER + 0x100);
            Function untouched = function(program, CALLER + 0x200);
            Function target = function(program, TARGET);
            String original = target.getPrototypeString(false, false);
            var originalBody = new ghidra.program.model.address.AddressSet(first.getBody());
            String before = decompile(program, first);
            long modification = program.getModificationNumber();
            var result = Il2CppSharedGenericCallAnalyzer.analyze(program, List.of(first, second, untouched),
                    Optional.empty(), Optional.of(catalog(SIGNATURE)), monitor);
            require(result.provenCalls() == 2 && result.candidateFunctions() == 3,
                    "reference proof count: " + result);
            require(program.getModificationNumber() == modification, "proof mutated program");
            var published = Il2CppSharedGenericCallPublisher.publish(program, result.proofs(), monitor);
            require(published.added() == 2, "local overrides were not added");
            require(target.getPrototypeString(false, false).equals(original), "global callee changed");
            require(first.getBody().equals(originalBody), "function body changed");
            require(HighFunction.findOverrideSpace(untouched) == null, "unmatched call received override");
            String firstText = decompile(program, first);
            String secondText = decompile(program, second);
            require(!before.contains("->score") && firstText.contains("->score"), "return field was not recovered: " + firstText);
            require(secondText.contains("->count"), "second local return type missing: " + secondText);
            long repeatedAt = program.getModificationNumber();
            var repeated = Il2CppSharedGenericCallPublisher.publish(program, result.proofs(), monitor);
            require(repeated.added() == 0 && repeated.retained() == 2 &&
                    program.getModificationNumber() == repeatedAt, "repeat was not idempotent");

            var cancelled = new TaskMonitorAdapter(true);
            cancelled.cancel();
            try {
                Il2CppSharedGenericCallAnalyzer.analyze(program, List.of(first),
                        Optional.empty(), Optional.of(catalog(SIGNATURE)), cancelled);
                throw new AssertionError("cancelled analysis ran");
            }
            catch (ghidra.util.exception.CancelledException expected) {
                require(program.getModificationNumber() == repeatedAt, "cancelled analysis mutated program");
            }
            try {
                Il2CppSharedGenericCallPublisher.publish(program, result.proofs(), cancelled);
                throw new AssertionError("cancelled publication ran");
            }
            catch (ghidra.util.exception.CancelledException expected) {
                require(program.getModificationNumber() == repeatedAt, "cancelled publication mutated program");
            }
            var proof = result.proofs().getFirst();
            var conflict = new Il2CppSharedGenericCallAnalyzer.ProvenCall(proof.callsite(), proof.target(),
                    proof.methodInfo(), proof.methodAddress(), proof.methodInfoAddress(),
                    new GenericCallContract.ReferenceReturn(SIGNATURE.replace("Sample_Item", "Sample_Other"), 7));
            try {
                Il2CppSharedGenericCallPublisher.publish(program, List.of(conflict), monitor);
                throw new AssertionError("conflicting local override was replaced");
            }
            catch (IllegalStateException expected) {
                require(decompile(program, first).equals(firstText), "conflict changed the original output");
            }
            int mutation = program.startTransaction("change synthetic token");
            try {
                program.getMemory().setLong(address(program, SLOT), 0);
            }
            finally {
                program.endTransaction(mutation, true);
            }
            try {
                Il2CppSharedGenericCallPublisher.publish(program, result.proofs(), monitor);
                throw new AssertionError("stale MethodInfo evidence was accepted");
            }
            catch (IllegalStateException expected) {
                require(program.getMemory().getLong(address(program, SLOT)) == 0, "stale publication changed token");
                require(target.getPrototypeString(false, false).equals(original), "stale publication changed callee");
                require(first.getBody().equals(originalBody), "stale publication changed body");
                require(decompile(program, first).equals(firstText), "stale publication changed first override");
                require(decompile(program, second).equals(secondText), "stale publication changed second override");
                require(HighFunction.findOverrideSpace(untouched) == null, "stale publication added an override");
            }
        }
        finally {
            program.release(this);
        }
    }

    private void negative(String mode) throws Exception {
        ProgramDB program = fixture(0, false, mode);
        try {
            Function caller = function(program, CALLER);
            long modification = program.getModificationNumber();
            var result = Il2CppSharedGenericCallAnalyzer.analyze(program, List.of(caller),
                    Optional.empty(), Optional.of(catalog(SIGNATURE)), monitor);
            require(result.provenCalls() == 0, "unproved case accepted: " + mode);
            require(program.getModificationNumber() == modification, "rejection mutated program: " + mode);
            var published = Il2CppSharedGenericCallPublisher.publish(program, result.proofs(), monitor);
            require(published.added() == 0 && HighFunction.findOverrideSpace(caller) == null,
                    "rejected call gained an override: " + mode);
        }
        finally {
            program.release(this);
        }
    }

    private void flowCase(String mode, boolean accepted) throws Exception {
        ProgramDB program = fixture(0, true, mode);
        try {
            Function caller = function(program, CALLER);
            String original = function(program, TARGET).getPrototypeString(false, false);
            long modification = program.getModificationNumber();
            var result = Il2CppSharedGenericCallAnalyzer.analyze(program, List.of(caller),
                    Optional.empty(), Optional.of(catalog(SIGNATURE)), monitor);
            require(result.provenCalls() == (accepted ? 1 : 0), mode + ": " + result);
            require(program.getModificationNumber() == modification, mode + " proof changed program");
            var published = Il2CppSharedGenericCallPublisher.publish(program, result.proofs(), monitor);
            require(published.added() == (accepted ? 1 : 0), mode + " publication count");
            require(function(program, TARGET).getPrototypeString(false, false).equals(original), mode + " changed callee");
            if (accepted) require(decompile(program, caller).contains("->score"), mode + " did not recover field");
            else require(HighFunction.findOverrideSpace(caller) == null, mode + " added an override");
        }
        finally {
            program.release(this);
        }
    }

    private void instructionBudget() throws Exception {
        ProgramDB program = fixture(0, true, "valid");
        try {
            Function caller = function(program, CALLER);
            int transaction = program.startTransaction("extend synthetic body");
            try {
                Address start = address(program, 0x10000);
                byte[] instruction = program.getListing().getInstructionAt(address(program, CALLER + 4)).getBytes();
                byte[] bytes = new byte[8193 * instruction.length];
                for (int offset = 0; offset < bytes.length; offset += instruction.length) {
                    System.arraycopy(instruction, 0, bytes, offset, instruction.length);
                }
                var block = program.getMemory().createInitializedBlock(".padding", start, bytes.length,
                        (byte) 0, monitor, false);
                block.setExecute(true);
                program.getMemory().setBytes(start, bytes);
                var extra = new ghidra.program.model.address.AddressSet(start, block.getEnd());
                require(new ghidra.app.cmd.disassemble.DisassembleCommand(start, extra, true)
                        .applyTo(program, monitor), "budget fixture disassembly failed");
                var body = new ghidra.program.model.address.AddressSet(caller.getBody());
                body.add(extra);
                caller.setBody(body);
            }
            finally {
                program.endTransaction(transaction, true);
            }
            long modification = program.getModificationNumber();
            var result = Il2CppSharedGenericCallAnalyzer.analyze(program, List.of(caller),
                    Optional.empty(), Optional.of(catalog(SIGNATURE)), monitor);
            require(result.provenCalls() == 0, "instruction budget was ignored");
            require(program.getModificationNumber() == modification &&
                    HighFunction.findOverrideSpace(caller) == null, "budget rejection changed program");
        }
        finally {
            program.release(this);
        }
    }

    private ProgramDB fixture(long imageBase, boolean got, String mode) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("AARCH64:LE:64:v8A"));
        var program = new ProgramDB("reference-return-fixture", language, language.getDefaultCompilerSpec(), this);
        int tx = program.startTransaction("build reference-return fixture");
        boolean commit = false;
        try {
            program.setImageBase(program.getAddressFactory().getDefaultAddressSpace().getAddress(imageBase), true);
            for (String name : List.of("Sample_Item_o", "Sample_Other_o", "Sample_Box_o", "MethodInfo", "Il2CppObject")) {
                if (mode.equals("missing-type") && name.equals("Sample_Item_o")) continue;
                var type = new StructureDataType(GhidraTypeImporter.ROOT, name, 24, program.getDataTypeManager());
                if (!mode.equals("opaque-type") || !name.equals("Sample_Item_o")) {
                    String field = name.equals("Sample_Item_o") ? "score" : name.equals("Sample_Other_o") ? "count" : "value";
                    type.replaceAtOffset(16, IntegerDataType.dataType, 4, field, null);
                }
                program.getDataTypeManager().addDataType(type, DataTypeConflictHandler.DEFAULT_HANDLER);
            }
            if (mode.equals("conflict-type")) {
                var conflict = new StructureDataType(GhidraTypeImporter.ROOT, "Sample_Item_o.conflict", 8);
                conflict.add(IntegerDataType.dataType);
                program.getDataTypeManager().addDataType(conflict, DataTypeConflictHandler.DEFAULT_HANDLER);
            }
            var code = program.getMemory().createInitializedBlock(".text", address(program, CALLER), 4096, (byte) 0, monitor, false);
            code.setExecute(!mode.equals("non-executable"));
            program.getMemory().createInitializedBlock(".data", address(program, SLOT), 256, (byte) 0, monitor, false);
            var gotBlock = program.getMemory().createInitializedBlock(".got", address(program, 0x4000), 256, (byte) 0, monitor, false);
            program.getMemory().createUninitializedBlock(".bss", address(program, 0x5000), 16, false);
            gotBlock.setWrite(mode.equals("writable-got"));
            for (int index = 0; index < 3; index++) {
                program.getMemory().setLong(address(program, SLOT + 8 * index),
                        (6L << 29) | ((7L + index + (mode.equals("token") ? 1 : 0)) << 1) | 1);
                program.getMemory().setLong(address(program, 0x4000 + 8 * index), address(program, SLOT + 8 * index).getOffset());
            }
            var assembler = Assemblers.getAssembler(program);
            assembler.assemble(address(program, TARGET), "ldr x0,[x0,#0x10]", "ret");
            assembler.assemble(address(program, TARGET + 0x40), "ret");
            for (int index = 0; index < 3; index++) {
                var lines = new ArrayList<String>();
                lines.add("stp x29,x30,[sp,#-0x10]!");
                lines.add("mov x29,sp");
                if (mode.equals("branch")) lines.add("cbz x0,0x" + address(program, CALLER + index * 0x100 + 24));
                lines.add("adrp x8,0x" + address(program, got ? 0x4000 : SLOT));
                lines.add("add x8,x8,#" + (index * 8));
                if (got) lines.add("ldr x8,[x8]");
                if (mode.equals("float-compare")) lines.add("fcmp s0,#0.0");
                if (mode.equals("select-unrelated")) lines.add("csel w9,w10,w11,lt");
                if (mode.equals("select-slot")) lines.add("csel x8,x8,x9,lt");
                if (mode.equals("select-slot-alias")) lines.add("csel w8,w8,w9,lt");
                if (mode.equals("slot-store")) lines.add("str x0,[x8]");
                if (mode.equals("partial-slot-store")) lines.add("strb w0,[x8,#1]");
                if (mode.equals("uninitialized-store")) {
                    lines.add("adrp x9,0x" + address(program, 0x5000));
                    lines.add("strb wzr,[x9]");
                }
                if (mode.equals("null-check")) {
                    lines.add("cbz x0,0x" + address(program, CALLER + index * 0x100 + 0x80));
                    assembler.assemble(address(program, CALLER + index * 0x100 + 0x80),
                            "ldp x29,x30,[sp],#0x10", "ret");
                }
                if (mode.endsWith("-join")) {
                    long fork = CALLER + index * 0x100 + lines.size() * 4;
                    lines.add("cbz x0,0x" + address(program, fork + 12));
                    lines.add("mov x9,x8");
                    lines.add("b 0x" + address(program, fork + 16));
                    lines.add(mode.equals("equal-join") ? "mov x9,x8" :
                            mode.equals("conflicting-join") ? "add x9,x8,#8" : "mov x9,x10");
                    lines.add("ldr x2,[x9]");
                }
                else if (mode.endsWith("-loop")) {
                    lines.add("mov w10,#2");
                    long loop = CALLER + index * 0x100 + lines.size() * 4;
                    lines.add("ldr x2,[x8]");
                    if (mode.equals("changing-loop")) lines.add("add x8,x8,#8");
                    lines.add("subs w10,w10,#1");
                    lines.add("b.ne 0x" + address(program, loop));
                }
                else if (mode.equals("preserved-call") || mode.equals("volatile-call")) {
                    lines.add("mov x19,x8");
                    lines.add("bl 0x" + address(program, TARGET + 0x40));
                    lines.add(mode.equals("preserved-call") ? "ldr x2,[x19]" : "ldr x2,[x8]");
                }
                else lines.add("ldr x2,[x8]");
                if (mode.equals("clobber")) lines.add("bl 0x" + address(program, TARGET + 0x40));
                if (mode.equals("register")) lines.add("mov w2,#0");
                if (mode.equals("store")) lines.add("str x0,[sp]");
                if (mode.equals("hidden-flow")) lines.add("svc 0");
                if (mode.equals("select-method-info")) lines.add("csel x2,x2,x9,lt");
                if (mode.equals("window")) {
                    for (int padding = 0; padding < 25; padding++) lines.add("mov w1,#0");
                }
                lines.add("mov w1,#0");
                lines.add("bl 0x" + address(program, mode.equals("wrong-target") ? TARGET + 0x40 : TARGET));
                if (mode.equals("compare-after-call")) lines.add("fcmp s0,s1");
                lines.add("ldr w0,[x0,#0x10]");
                lines.add("ldp x29,x30,[sp],#0x10");
                lines.add("ret");
                assembler.assemble(address(program, CALLER + index * 0x100), lines.toArray(String[]::new));
            }
            for (long offset : new long[] { TARGET, TARGET + 0x40, CALLER, CALLER + 0x100, CALLER + 0x200 }) {
                require(new CreateFunctionCmd(address(program, offset)).applyTo(program, monitor), "fixture function failed");
            }
            if (mode.equals("external-entry")) {
                program.getReferenceManager().addMemoryReference(address(program, TARGET + 0x80),
                        address(program, CALLER + 20), ghidra.program.model.symbol.RefType.UNCONDITIONAL_JUMP,
                        SourceType.USER_DEFINED, 0);
            }
            String targetSignature = (mode.equals("return-abi") ? "int64_t" : "Il2CppObject*") +
                    " Sample_Read (Sample_Box_o* __this, " + (mode.equals("parameter-abi") ? "float" : "int32_t") +
                    " index, const MethodInfo* method);";
            var stats = new GhidraMethodImporter(program, monitor).importMethods(List.of(
                    new ScriptMethodReader.ScriptMethod(TARGET, "Sample_Read", targetSignature, "ppip", null)));
            require(stats.failed() == 0, "target signature import failed: " + stats);
            function(program, TARGET + 0x40).setCallingConvention(program.getCompilerSpec().getDefaultCallingConvention().getName());
            commit = true;
            return program;
        }
        finally {
            program.endTransaction(tx, commit);
            if (!commit) program.release(this);
        }
    }

    private Il2CppReferenceGenericCallCatalog catalog(String signature) throws Exception {
        var rows = List.of(new Il2CppReferenceGenericCallCatalog.Entry(SLOT, 7, TARGET, signature),
                new Il2CppReferenceGenericCallCatalog.Entry(SLOT + 8, 8, TARGET, signature.replace("Sample_Item", "Sample_Other")));
        var data = new ScriptMethodReader.ScriptData(List.of(), List.of(), List.of(), List.of(),
                Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(rows));
        return Il2CppReferenceGenericCallCatalog.fromScript(data).orElseThrow();
    }

    private String decompile(ProgramDB program, Function function) {
        var decompiler = new DecompInterface();
        try {
            require(decompiler.openProgram(program), "decompiler open failed");
            var result = decompiler.decompileFunction(function, 30, monitor);
            require(result.decompileCompleted(), "fixture decompilation failed: " + result.getErrorMessage());
            return result.getDecompiledFunction().getC();
        }
        finally {
            decompiler.dispose();
        }
    }

    private static Function function(ProgramDB program, long offset) {
        return program.getFunctionManager().getFunctionAt(address(program, offset));
    }

    private static Address address(ProgramDB program, long offset) {
        return program.getImageBase().add(offset);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
