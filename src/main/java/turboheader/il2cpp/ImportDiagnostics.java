package turboheader.il2cpp;

/** User-facing diagnostics shared by the script and the lightweight test harness. */
public final class ImportDiagnostics {
    private ImportDiagnostics() {
    }

    public static String inferredExtentWarning(int count) {
        return String.format(
                "TurboHeader warning: %,d structure extents were derived from imported field " +
                "offsets and C type sizes because the selected source had no " +
                "runtime-authoritative total size. Field offsets were not inferred.",
                count);
    }
}
