package turboheader.il2cpp;

import java.util.ArrayDeque;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/** Bounded traversal of the SSA definition graph behind one decompiler value. */
final class PcodeValueTracer {
    private static final int MAX_VISITED_VALUES = 128;

    private PcodeValueTracer() {
    }

    static boolean referencesAny(Varnode value, Set<Address> expectedAddresses) {
        return !referencedAddresses(value, expectedAddresses).isEmpty();
    }

    static Set<Address> referencedAddresses(Varnode value, Set<Address> expectedAddresses) {
        Set<Long> expectedOffsets = new HashSet<>();
        var expectedByOffset = new java.util.HashMap<Long, Address>();
        for (Address address : expectedAddresses) {
            expectedOffsets.add(address.getOffset());
            expectedByOffset.put(address.getOffset(), address);
        }

        var pending = new ArrayDeque<Varnode>();
        Set<Varnode> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        Set<Address> found = new HashSet<>();
        pending.add(value);
        while (!pending.isEmpty() && visited.size() < MAX_VISITED_VALUES) {
            Varnode current = pending.removeLast();
            if (!visited.add(current)) {
                continue;
            }
            Address address = current.getAddress();
            if (address != null &&
                    ((address.isMemoryAddress() && expectedAddresses.contains(address)) ||
                    (current.isConstant() && expectedOffsets.contains(current.getOffset())))) {
                Address matched = address.isMemoryAddress()
                        ? address
                        : expectedByOffset.get(current.getOffset());
                if (matched != null) {
                    found.add(matched);
                }
            }

            PcodeOp definition = current.getDef();
            if (definition == null) {
                continue;
            }
            for (int index = 0; index < definition.getNumInputs(); index++) {
                Varnode input = definition.getInput(index);
                if (input != null && !visited.contains(input)) {
                    pending.add(input);
                }
            }
        }
        return Set.copyOf(found);
    }
}
