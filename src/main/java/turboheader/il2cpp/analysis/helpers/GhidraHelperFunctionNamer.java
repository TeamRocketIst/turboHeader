package turboheader.il2cpp.analysis.helpers;

import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/** Applies conservative IL2CPP helper names to actual Ghidra functions. */
public final class GhidraHelperFunctionNamer {
    public RenameOutcome rename(Function function, Il2CppHelperKind kind)
            throws DuplicateNameException, InvalidInputException {
        String expected = Il2CppHelperNames.mappedName(
                kind, function.getEntryPoint().getOffset());
        if (expected.equals(function.getName())) {
            return RenameOutcome.ALREADY_NAMED;
        }

        SourceType source = function.getSymbol().getSource();
        if (source != SourceType.DEFAULT && source != SourceType.ANALYSIS) {
            return RenameOutcome.PRESERVED;
        }

        function.setName(expected, SourceType.ANALYSIS);
        return RenameOutcome.RENAMED;
    }

    public enum RenameOutcome {
        RENAMED,
        ALREADY_NAMED,
        PRESERVED
    }
}
