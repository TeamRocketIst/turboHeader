package turboheader.il2cpp.types;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.function.Consumer;

import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.framework.Application;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import turboheader.il2cpp.Il2CppLayoutPolicy;

/** Imports an IL2CPP header through Ghidra's general-purpose CParser. */
public final class GhidraCParserTypeImportStrategy implements Il2CppTypeImportStrategy {
    private final Program program;
    private final TaskMonitor monitor;
    private final Consumer<String> output;

    public GhidraCParserTypeImportStrategy(Program program, TaskMonitor monitor,
            Consumer<String> output) {
        this.program = Objects.requireNonNull(program, "program");
        this.monitor = monitor == null ? TaskMonitor.DUMMY : monitor;
        this.output = Objects.requireNonNull(output, "output");
    }

    @Override
    public void importTypes(Path header, Path offsets, int pointerSize,
            Il2CppLayoutPolicy layoutPolicy) throws Exception {
        if (offsets != null || layoutPolicy != Il2CppLayoutPolicy.ALLOW_INFERRED) {
            throw new IllegalArgumentException(
                    "Ghidra CParser does not consume external IL2CPP layout offsets");
        }
        if (pointerSize != 4 && pointerSize != 8) {
            throw new IllegalArgumentException(
                    "Program pointer size must be 4 or 8, got " + pointerSize);
        }

        output.accept("TurboHeader: preparing IL2CPP header for Ghidra CParser...");
        Path temporaryDirectory = Application.getUserTempDirectory().toPath();
        long started = System.nanoTime();
        try (var prepared = CParserHeaderAdapter.prepare(
                header, pointerSize, temporaryDirectory)) {
            String[] filenames = { prepared.path().toString() };
            String[] includePaths = {};
            var result = CParserUtils.parseHeaderFiles(
                    new DataTypeManager[0], filenames, includePaths,
                    preprocessorArguments(), program.getDataTypeManager(), monitor);
            if (!result.successful()) {
                throw new IOException("Ghidra CParser did not import the IL2CPP header");
            }
            double elapsed = (System.nanoTime() - started) / 1_000_000_000.0;
            output.accept(String.format(
                    "TurboHeader CParser: imported header in %.3f s; converted %,d inheritance declarations.",
                    elapsed, prepared.inheritanceConversions()));
        }
    }

    private String[] preprocessorArguments() {
        List<String> arguments = new ArrayList<>();
        int pointerBits = program.getDefaultPointerSize() * 8;
        arguments.add("-D__WORDSIZE=" + pointerBits);
        if (pointerBits == 64) {
            arguments.add("-D__LP64__");
            arguments.add("-D_LP64");
        }

        String processor = program.getLanguage().getProcessor().toString()
                .toLowerCase(Locale.ROOT);
        if (processor.contains("x86")) {
            arguments.add(pointerBits == 64 ? "-D__x86_64__" : "-D__i386__");
            arguments.add(pointerBits == 64 ? "-D_AMD64_" : "-D_X86_");
        }
        else if (processor.contains("aarch64") || processor.contains("aarch")) {
            arguments.add("-D__aarch64__");
        }
        else if (processor.contains("arm")) {
            arguments.add("-D__arm__");
        }
        else if (processor.contains("mips")) {
            arguments.add("-D__mips__");
        }

        String compiler = program.getCompilerSpec().getCompilerSpecID().getIdAsString()
                .toLowerCase(Locale.ROOT);
        if (compiler.contains("gcc")) {
            arguments.add("-D__GNUC__=1");
            arguments.add("-D__STDC__=1");
            arguments.add("-D_GNU_SOURCE=1");
        }
        else if (compiler.contains("windows") || compiler.contains("visualstudio")) {
            arguments.add("-D_MSC_VER=1900");
            arguments.add("-DWIN32=1");
            arguments.add("-D_WIN32=1");
            if (pointerBits == 64) {
                arguments.add("-DWIN64=1");
                arguments.add("-D_WIN64=1");
            }
        }
        return arguments.toArray(String[]::new);
    }
}
