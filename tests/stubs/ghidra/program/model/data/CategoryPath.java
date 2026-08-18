package ghidra.program.model.data;
import java.util.Objects;
public final class CategoryPath {
    private final String path;
    public CategoryPath(String path) { this.path = path; }
    @Override public String toString() { return path; }
    @Override public boolean equals(Object o) { return o instanceof CategoryPath c && Objects.equals(path,c.path); }
    @Override public int hashCode() { return path.hashCode(); }
}
