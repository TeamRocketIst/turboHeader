package turboheader.il2cpp.analysis;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

final class ExactSsaValueResolver<N> {
    private static final int MAX_VALUES = 128;
    private static final int MAX_EDGES = MAX_VALUES * MAX_VALUES;
    private static final int MAX_STATE_CHANGES = MAX_VALUES * 3;

    private final ValueGraph<N> graph;

    ExactSsaValueResolver(ValueGraph<N> graph) {
        this.graph = Objects.requireNonNull(graph, "graph");
    }

    Origin resolve(N root) {
        if (root == null) {
            return Origin.unknown();
        }

        Graph<N> reachable = collect(root);
        if (reachable == null) {
            return Origin.unknown();
        }

        Map<N, Origin> origins = new IdentityHashMap<>();
        for (N node : reachable.nodes()) {
            origins.put(node, Origin.unset());
        }

        var pending = new ArrayDeque<N>(reachable.nodes());
        Set<N> queued = Collections.newSetFromMap(new IdentityHashMap<>());
        queued.addAll(reachable.nodes());
        int stateChanges = 0;
        while (!pending.isEmpty()) {
            N node = pending.removeFirst();
            queued.remove(node);
            Origin previous = origins.get(node);
            Origin candidate = evaluate(reachable.values().get(node), origins);
            Origin next = join(previous, candidate);
            if (next.equals(previous)) {
                continue;
            }
            if (++stateChanges > MAX_STATE_CHANGES) {
                return Origin.unknown();
            }
            origins.put(node, next);
            for (N dependent : reachable.dependents().getOrDefault(node, List.of())) {
                if (queued.add(dependent)) {
                    pending.addLast(dependent);
                }
            }
        }

        Origin result = origins.get(root);
        return result.kind() == Kind.UNSET ? Origin.unknown() : result;
    }

    private Graph<N> collect(N root) {
        List<N> nodes = new ArrayList<>();
        Map<N, Value<N>> values = new IdentityHashMap<>();
        Map<N, List<N>> dependents = new IdentityHashMap<>();
        Set<N> discovered = Collections.newSetFromMap(new IdentityHashMap<>());
        var pending = new ArrayDeque<N>();
        discovered.add(root);
        pending.add(root);
        int edges = 0;

        while (!pending.isEmpty()) {
            N node = pending.removeFirst();
            Value<N> value = Objects.requireNonNull(graph.describe(node), "value");
            nodes.add(node);
            values.put(node, value);
            for (N input : value.inputs()) {
                if (++edges > MAX_EDGES) {
                    return null;
                }
                dependents.computeIfAbsent(input, ignored -> new ArrayList<>()).add(node);
                if (discovered.add(input)) {
                    if (discovered.size() > MAX_VALUES) {
                        return null;
                    }
                    pending.addLast(input);
                }
            }
        }
        return new Graph<>(List.copyOf(nodes), values, dependents);
    }

    private Origin evaluate(Value<N> value, Map<N, Origin> origins) {
        return switch (value.operation()) {
            case UNKNOWN -> Origin.unknown();
            case EXACT_TYPE -> value.value() >= 0 && value.value() <= Integer.MAX_VALUE
                    ? new Origin(Kind.EXACT_TYPE, value.value())
                    : Origin.unknown();
            case EXACT_CONSTANT -> new Origin(Kind.EXACT_CONSTANT, value.value());
            case ALLOCATION -> allocation(value.inputs(), origins);
            case COPY -> value.inputs().size() == 1
                    ? origins.get(value.inputs().getFirst())
                    : Origin.unknown();
            case MERGE -> merge(value.inputs(), origins);
        };
    }

    private Origin allocation(List<N> inputs, Map<N, Origin> origins) {
        if (inputs.size() != 1) {
            return Origin.unknown();
        }
        Origin type = origins.get(inputs.getFirst());
        return switch (type.kind()) {
            case UNSET -> Origin.unset();
            case EXACT_TYPE -> new Origin(Kind.EXACT_ALLOCATION, type.value());
            case CONFLICT -> Origin.conflict();
            default -> Origin.unknown();
        };
    }

    private Origin merge(List<N> inputs, Map<N, Origin> origins) {
        if (inputs.isEmpty()) {
            return Origin.unknown();
        }
        Origin result = Origin.unset();
        for (N input : inputs) {
            result = join(result, origins.get(input));
        }
        return result;
    }

    private Origin join(Origin first, Origin second) {
        if (first.equals(second) || second.kind() == Kind.UNSET) {
            return first;
        }
        if (first.kind() == Kind.UNSET) {
            return second;
        }
        if (first.kind() == Kind.UNKNOWN || second.kind() == Kind.UNKNOWN) {
            return Origin.unknown();
        }
        if (first.kind() == Kind.CONFLICT || second.kind() == Kind.CONFLICT) {
            return Origin.conflict();
        }
        return Origin.conflict();
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
        UNSET,
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

        static Origin unset() {
            return new Origin(Kind.UNSET, 0);
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

    private record Graph<N>(List<N> nodes, Map<N, Value<N>> values,
            Map<N, List<N>> dependents) {
    }
}
