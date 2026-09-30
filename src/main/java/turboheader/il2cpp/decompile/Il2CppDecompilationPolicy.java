package turboheader.il2cpp.decompile;

public final class Il2CppDecompilationPolicy {
    public static final int LEGACY_SEQUENTIAL = 0;
    public static final int MIN_PARALLEL_WORKERS = 1;
    public static final int MAX_WORKERS = 12;
    public static final int MAX_DELEGATE_WORKERS = 4;
    public static final int TIMEOUT_SECONDS = 60;

    private Il2CppDecompilationPolicy() {
    }

    public static int delegateWorkers(int decompileJobs) {
        if (decompileJobs < MIN_PARALLEL_WORKERS || decompileJobs > MAX_WORKERS) {
            throw new IllegalArgumentException("decompileJobs must be between 1 and 12");
        }
        return Math.min(decompileJobs, MAX_DELEGATE_WORKERS);
    }
}
