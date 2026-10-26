"""Finite reaching writes for certified stack slots at ordinary CALL sites.

This refines outgoing arguments only. Ordinary memory stays flow-insensitive.
An exact singleton stack address overwrites reaching bytes; ambiguous addresses
weakly add writes. Dynamic/foreign aliases are retained by the Datalog fallback.
"""
from collections import defaultdict, deque


def prepare(directory, values, complete):
    from memory_model import read_rows, write_rows

    statements = {int(stmt): (func, int(bb), int(order))
                  for stmt, func, bb, _, order in read_rows(directory, 'statement')}
    stores, certified = {}, []
    for stmt, func, _, size, address, _ in read_rows(directory, 'store'):
        stmt, size, address = int(stmt), int(size), int(address)
        candidates = values.get(address, set())
        if (address not in complete or not candidates or not 0 < size <= 256
                or not all(value[0] == 's' and value[1] == func for value in candidates)):
            continue
        offsets = {value[2] for value in candidates}
        stores[stmt] = (offsets, size)
        certified.extend((stmt, offset) for offset in offsets)
    write_rows(directory, 'certified_stack_store', certified)

    blocks = {(func, int(bb)) for func, bb, _ in read_rows(directory, 'block')}
    predecessors, successors = defaultdict(set), defaultdict(set)
    for func, source, dest, _ in read_rows(directory, 'edge'):
        source, dest = (func, int(source)), (func, int(dest))
        if source in blocks and dest in blocks:
            predecessors[dest].add(source)
            successors[source].add(dest)
    calls = {int(stmt) for stmt, *_ in read_rows(directory, 'call')}
    events = defaultdict(list)
    for stmt in calls | stores.keys():
        if stmt in statements:
            func, bb, order = statements[stmt]
            if (func, bb) in blocks:
                events[(func, bb)].append((order, stmt))
    for sequence in events.values():
        sequence.sort()

    def apply(state, stmt):
        if stmt not in stores:
            return state
        offsets, size = stores[stmt]
        written = {byte for offset in offsets for byte in range(offset, offset+size)}
        if len(offsets) == 1:
            state = {(byte, source) for byte, source in state if byte not in written}
        return state | {(byte, stmt) for byte in written}

    incoming, outgoing = defaultdict(set), defaultdict(set)
    queue, queued = deque(sorted(blocks)), set(blocks)
    while queue:
        block = queue.popleft()
        queued.remove(block)
        state = set().union(*(outgoing[pred] for pred in predecessors[block]))
        incoming[block] = state
        for _, stmt in events[block]:
            state = apply(state, stmt)
        if state != outgoing[block]:
            outgoing[block] = state
            for dest in successors[block]:
                if dest not in queued:
                    queue.append(dest)
                    queued.add(dest)

    snapshots, reaching = [], []
    for block, sequence in events.items():
        state = incoming[block]
        for _, stmt in sequence:
            if stmt in calls:
                snapshots.append((stmt,))
                reaching.extend((stmt, source) for _, source in state)
            state = apply(state, stmt)
    write_rows(directory, 'call_stack_snapshot', snapshots)
    write_rows(directory, 'call_stack_store', reaching)
