package turboheader.il2cpp.analysis;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

final class ExactSsaValueResolver<N> {
    private static final int MAX_VALUES = 128;

    private final ValueGraph<N> graph;
    private final Map<N, Origin> resolved = new IdentityHashMap<>();
    private final Set<N> active = Collections.newSetFromMap(new IdentityHashMap<>());
    private int visited;

    ExactSsaValueResolver(ValueGraph<N> graph) {
        this.graph = Objects.requireNonNull(graph, "graph");
    }

    Origin resolve(N node) {
        if (node == null) {
            return Origin.unknown();
        }
        Origin known = resolved.get(node);
        if (known != null) {
            return known;
        }
        if (visited >= MAX_VALUES || !active.add(node)) {
            return Origin.unknown();
        }

        visited++;
        Origin result;
        try {
            result = evaluate(Objects.requireNonNull(graph.describe(node), "value"));
        }
        finally {
            active.remove(node);
        }
        resolved.put(node, result);
        return result;
    }

    private Origin evaluate(Value<N> value) {
        return switch (value.operation()) {
            case UNKNOWN -> Origin.unknown();
            case EXACT_TYPE -> value.value() >= 0 && value.value() <= Integer.MAX_VALUE
                    ? new Origin(Kind.EXACT_TYPE, value.value())
                    : Origin.unknown();
            case EXACT_CONSTANT -> new Origin(Kind.EXACT_CONSTANT, value.value());
            case ALLOCATION -> allocation(value.inputs());
            case COPY -> value.inputs().size() == 1
                    ? resolve(value.inputs().getFirst())
                    : Origin.unknown();
            case MERGE -> merge(value.inputs());
        };
    }

    private Origin allocation(List<N> inputs) {
        if (inputs.size() != 1) {
            return Origin.unknown();
        }
        Origin type = resolve(inputs.getFirst());
        return type.kind() == Kind.EXACT_TYPE
                ? new Origin(Kind.EXACT_ALLOCATION, type.value())
                : Origin.unknown();
    }

    private Origin merge(List<N> inputs) {
        if (inputs.isEmpty()) {
            return Origin.unknown();
        }

        Origin exact = null;
        boolean unknown = false;
        for (N input : inputs) {
            Origin origin = resolve(input);
            if (origin.kind() == Kind.CONFLICT) {
                return Origin.conflict();
            }
            if (origin.kind() == Kind.UNKNOWN) {
                unknown = true;
                continue;
            }
            if (exact == null) {
                exact = origin;
            }
            else if (!exact.equals(origin)) {
                return Origin.conflict();
            }
        }
        return unknown || exact == null ? Origin.unknown() : exact;
    }

    enum Operation {
        UNKNOWN,
        EXACT_TYPE,
        EXACT_CONSTANT,
        ALLOCATION,
        COPY,
        MERGE
    }

    enum Kind {
        UNKNOWN,
        EXACT_TYPE,
        EXACT_CONSTANT,
        EXACT_ALLOCATION,
        CONFLICT
    }

    record Origin(Kind kind, long value) {
        Origin {
            Objects.requireNonNull(kind, "kind");
        }

        static Origin unknown() {
            return new Origin(Kind.UNKNOWN, 0);
        }

        static Origin conflict() {
            return new Origin(Kind.CONFLICT, 0);
        }
    }

    record Value<N>(Operation operation, long value, List<N> inputs) {
        Value {
            Objects.requireNonNull(operation, "operation");
            inputs = List.copyOf(inputs);
        }
    }

    interface ValueGraph<N> {
        Value<N> describe(N node);
    }
}
