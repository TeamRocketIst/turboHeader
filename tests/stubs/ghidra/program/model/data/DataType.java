package ghidra.program.model.data;
public interface DataType {
    int getLength();
    String getName();
    CategoryPath getCategoryPath();
    default String getDescription() { return null; }
    default void setDescription(String description) {}
}
