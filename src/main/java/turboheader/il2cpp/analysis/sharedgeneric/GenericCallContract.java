package turboheader.il2cpp.analysis.sharedgeneric;

public sealed interface GenericCallContract {
    String signature();

    record ResultBuffer(String signature) implements GenericCallContract {
    }

    record ReferenceReturn(String signature, int methodSpecIndex) implements GenericCallContract {
    }
}
