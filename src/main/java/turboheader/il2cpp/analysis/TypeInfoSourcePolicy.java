package turboheader.il2cpp.analysis;

final class TypeInfoSourcePolicy {
    private TypeInfoSourcePolicy() {
    }

    static boolean accepts(int pointerSize, Evidence evidence) {
        return pointerSize > 0 && evidence.dataLength() == pointerSize &&
                evidence.pointerData() && evidence.readable() && !evidence.writable() &&
                !evidence.executable() && evidence.valueReferenceCount() == 1 &&
                evidence.dataReference() && evidence.primaryReference() &&
                evidence.valueMatchesReference();
    }

    record Evidence(int dataLength, boolean pointerData, boolean readable,
            boolean writable, boolean executable, int valueReferenceCount,
            boolean dataReference, boolean primaryReference,
            boolean valueMatchesReference) {
    }
}
