package turboheader.il2cpp.analysis.ssa;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Resolves copies and unanimous SSA merges to one exact source value. */
public final class SsaIdentityResolver<N> {
    private static final int MAX_VALUES = 128;

    private final ValueGraph<N> graph;
    private final Map<N, Optional<N>> resolved = new IdentityHashMap<>();
    private final Set<N> active = Collections.newSetFromMap(new IdentityHashMap<>());
    private int visited;

    public SsaIdentityResolver(ValueGraph<N> graph) {
        this.graph = Objects.requireNonNull(graph, "graph");
    }

    public Optional<N> resolve(N node) {
        if (node == null) {
            return Optional.empty();
        }
        Optional<N> known = resolved.get(node);
        if (known != null) {
            return known;
        }
        if (visited >= MAX_VALUES || !active.add(node)) {
            return Optional.empty();
        }

        visited++;
        Optional<N> result;
        try {
            result = evaluate(node, Objects.requireNonNull(graph.describe(node), "value"));
        }
        finally {
            active.remove(node);
        }
        resolved.put(node, result);
        return result;
    }

    private Optional<N> evaluate(N node, Value<N> value) {
        return switch (value.operation()) {
            case ROOT -> Optional.of(node);
            case COPY -> value.inputs().size() == 1
                    ? resolve(value.inputs().getFirst())
                    : Optional.empty();
            case MERGE -> merge(value.inputs());
        };
    }

    private Optional<N> merge(List<N> inputs) {
        if (inputs.isEmpty()) {
            return Optional.empty();
        }

        N root = null;
        for (N input : inputs) {
            Optional<N> candidate = resolve(input);
            if (candidate.isEmpty()) {
                return Optional.empty();
            }
            if (root == null) {
                root = candidate.get();
            }
            else if (root != candidate.get()) {
                return Optional.empty();
            }
        }
        return Optional.of(root);
    }

    public enum Operation {
        ROOT,
        COPY,
        MERGE
    }

    public record Value<N>(Operation operation, List<N> inputs) {
        public Value {
            Objects.requireNonNull(operation, "operation");
            inputs = List.copyOf(inputs);
        }
    }

    @FunctionalInterface
    public interface ValueGraph<N> {
        Value<N> describe(N node);
    }
}
