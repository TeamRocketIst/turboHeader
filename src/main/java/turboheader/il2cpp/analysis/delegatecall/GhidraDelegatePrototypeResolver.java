package turboheader.il2cpp.analysis.delegatecall;

import java.util.ArrayList;
import java.util.Objects;

import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import turboheader.il2cpp.metadata.GhidraMethodImporter;

/** Converts one validated delegate prototype to Ghidra datatypes. */
public final class GhidraDelegatePrototypeResolver {
    private GhidraDelegatePrototypeResolver() {
    }

    public static FunctionSignature resolve(Program program,
            DelegateCallPrototype prototype) throws InvalidInputException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(prototype, "prototype");
        var types = new GhidraMethodImporter(program, TaskMonitor.DUMMY);
        var signature = new FunctionDefinitionDataType(
                GhidraMethodImporter.signatureCategory(),
                "__delegate_invoke_" + Integer.toUnsignedString(prototype.typeId()),
                program.getDataTypeManager());
        signature.setReturnType(types.resolveType(prototype.returnType(), false));

        var parameters = new ArrayList<ParameterDefinition>();
        for (var parameter : prototype.parameters()) {
            parameters.add(new ParameterDefinitionImpl(parameter.name(),
                    types.resolveType(parameter.type(), true), null));
        }
        signature.setArguments(parameters.toArray(ParameterDefinition[]::new));

        var convention = program.getCompilerSpec().getDefaultCallingConvention();
        if (convention != null) {
            signature.setCallingConvention(convention.getName());
        }
        return signature;
    }
}
