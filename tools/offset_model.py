"""Certify complete prepass values before using them to refine pointer offsets.

The scalar/affine prepass collects possible values. A nonempty set alone is not
proof that every source was modeled. This separate least fixed point certifies
all producers; cycles and unknown inputs conservatively retain generic flow.
"""
from collections import defaultdict
import re


def prepare(directory, values, top, mode):
    from memory_model import read_rows, write_rows, signed_displacement

    if mode not in {'block', 'heap-offset', 'offset'}:
        raise ValueError(f'Unknown memory model: {mode}')
    write_rows(directory, 'memory_model', [(mode,)])
    dependencies = defaultdict(set)
    producers, forbidden = set(), set(top)
    for relation in ('constant', 'stack_root'):
        producers.update(int(row[0]) for row in read_rows(directory, relation))
    for relation in ('copy', 'def_use'):
        for source, dest in read_rows(directory, relation):
            producers.add(int(dest))
            dependencies[int(dest)].add(int(source))
    for relation in ('binary', 'unary'):
        for dest, op, bits, *sources in read_rows(directory, relation):
            producers.add(int(dest))
            dependencies[int(dest)].update(map(int, sources))
            inputs = [values.get(int(source), set()) for source in sources]
            # A nonempty output can still omit unsupported alternatives, e.g.
            # Mul(phi(stack, 8), 2) computes 16 only for the numeric branch.
            if relation == 'unary':
                cast = re.fullmatch(r'(\d+)([US]?)to(\d+)', op)
                supported = cast is not None and all(
                    value[0] == 'n' or (value[0] == 's' and int(cast[3]) >= int(cast[1]))
                    for value in inputs[0])
            else:
                def supports(left, right):
                    kinds = (left[0], right[0])
                    if kinds == ('n', 'n'):
                        return op.startswith(('Add', 'Sub', 'And', 'Or', 'Xor', 'Mul'))
                    if op.startswith('Add'):
                        return kinds in {('s', 'n'), ('n', 's')}
                    if op.startswith('Sub'):
                        return kinds == ('s', 'n')
                    if op.startswith('And') and kinds in {('s', 'n'), ('n', 's')}:
                        mask = right if right[0] == 'n' else left
                        return signed_displacement(mask[1], int(bits)) == -1
                    return False
                supported = all(supports(left, right) for left in inputs[0] for right in inputs[1])
            if not supported:
                forbidden.add(int(dest))
    forbidden.update(int(row[0]) for row in read_rows(directory, 'unknown_seed'))
    forbidden.update(int(row[-1]) for row in read_rows(directory, 'load'))
    forbidden.update(int(row[-1]) for row in read_rows(directory, 'call_output'))
    roots = {int(row[0]) for row in read_rows(directory, 'stack_root')}
    forbidden.update(int(row[-1]) for row in read_rows(directory, 'entry_reg')
                     if int(row[-1]) not in roots)
    # Empty outputs include unsupported operations and never certify a value.
    pending = {eid for eid in producers if values.get(eid) and eid not in forbidden}
    complete = set()
    while True:
        ready = {eid for eid in pending if dependencies[eid] <= complete}
        if not ready:
            break
        complete.update(ready)
        pending.difference_update(ready)
    write_rows(directory, 'complete_value', ((eid,) for eid in complete))
    # Dynamic pointer arithmetic uses literal displacements only. A partially
    # known scalar set must never silently exclude unknown alternatives.
    write_rows(directory, 'offset_literal',
               ((int(eid), signed_displacement(int(value), int(bits)))
                for eid, bits, value in read_rows(directory, 'constant')
                if int(eid) in complete))
    callers = {int(row[0]): row[1] for row in read_rows(directory, 'call')}
    call_offsets = []
    for stmt, expression in read_rows(directory, 'call_stack'):
        stmt, expression = int(stmt), int(expression)
        candidates = values.get(expression, set())
        # All alternatives must be offsets in this caller's own frame. A
        # partial set, scalar SP, or foreign frame requires the fallback.
        if (expression in complete and candidates and stmt in callers
                and all(value[0] == 's' and value[1] == callers[stmt] for value in candidates)):
            call_offsets.extend((stmt, value[2]) for value in candidates)
    write_rows(directory, 'call_stack_offset', call_offsets)
    from stack_arguments import prepare as prepare_stack_arguments
    prepare_stack_arguments(directory, values, complete)
