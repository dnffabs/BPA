"""Finite scalar/affine prepass and conservative frame/section memory blocks.

Affine values are widened after eight alternatives. The points-to domain in
analysis.dl retains the block identity even when the offset is unknown.
"""
from collections import defaultdict, deque
import json
from pathlib import Path
import re


def read_rows(directory, relation):
    path = Path(directory) / f"{relation}.facts"
    return [line.split("\t") for line in path.read_text().splitlines() if line.strip()]


def write_rows(directory, relation, rows):
    text = ["\t".join(map(str, row)) for row in sorted(set(rows), key=str)]
    (Path(directory) / f"{relation}.facts").write_text("\n".join(text) + ("\n" if text else ""))


def wrap(value, bits):
    value &= (1 << bits) - 1
    return value - (1 << bits) if bits == 64 and value >= 1 << 63 else value


def affine_values(directory, limit=8):
    values, top, outgoing = defaultdict(set), set(), defaultdict(list)
    operations = []
    for relation in ("copy", "def_use"):
        for source, dest in read_rows(directory, relation):
            operations.append(("copy", int(dest), (int(source),), 0, ""))
    for dest, op, bits, left, right in read_rows(directory, "binary"):
        operations.append(("binary", int(dest), (int(left), int(right)), int(bits), op))
    for dest, op, bits, source in read_rows(directory, "unary"):
        operations.append(("unary", int(dest), (int(source),), int(bits), op))
    for index, (_, _, sources, _, _) in enumerate(operations):
        for source in sources:
            outgoing[source].append(index)
    queue, queued = deque(), set()

    def update(eid, candidates=(), unknown=False):
        if eid in top:
            return
        old = len(values[eid])
        values[eid].update(candidates)
        if unknown or len(values[eid]) > limit:
            top.add(eid)
            values[eid].clear()
        if eid in top or len(values[eid]) != old:
            for index in outgoing[eid]:
                if index not in queued:
                    queue.append(index)
                    queued.add(index)

    for eid, bits, value in read_rows(directory, "constant"):
        update(int(eid), [("n", int(value))])
    for eid, func in read_rows(directory, "stack_root"):
        update(int(eid), [("s", func, 0)])
    while queue:
        index = queue.popleft()
        queued.remove(index)
        kind, dest, sources, bits, op = operations[index]
        if any(source in top for source in sources):
            update(dest, unknown=True)
            continue
        candidates = set()
        if kind == "copy":
            candidates.update(values[sources[0]])
        elif kind == "unary":
            cast = re.fullmatch(r"(\d+)([US]?)to(\d+)", op)
            for value in values[sources[0]]:
                if value[0] == "n" and cast:
                    src_bits, sign, dest_bits = int(cast[1]), cast[2], int(cast[3])
                    num = value[1] & ((1 << src_bits) - 1)
                    if sign == "S" and num & (1 << (src_bits - 1)):
                        num -= 1 << src_bits
                    candidates.add(("n", wrap(num, dest_bits)))
                elif value[0] == "s" and cast and int(cast[3]) >= int(cast[1]):
                    candidates.add(value)
        else:
            for left in values[sources[0]]:
                for right in values[sources[1]]:
                    if op.startswith(("Add", "Sub")):
                        sign = -1 if op.startswith("Sub") else 1
                        if left[0] == right[0] == "n":
                            candidates.add(("n", wrap(left[1] + sign * right[1], bits)))
                        elif left[0] == "s" and right[0] == "n":
                            candidates.add(("s", left[1], left[2] + sign * right[1]))
                        elif sign == 1 and left[0] == "n" and right[0] == "s":
                            candidates.add(("s", right[1], right[2] + left[1]))
                    elif left[0] == right[0] == "n":
                        a, b = left[1], right[1]
                        if op.startswith("And"):
                            candidates.add(("n", wrap(a & b, bits)))
                        elif op.startswith("Or"):
                            candidates.add(("n", wrap(a | b, bits)))
                        elif op.startswith("Xor"):
                            candidates.add(("n", wrap(a ^ b, bits)))
                        elif op.startswith("Mul"):
                            candidates.add(("n", wrap(a * b, bits)))
        update(dest, candidates)
    return values, top


def build(directory):
    directory = Path(directory)
    metadata = json.loads((directory / "metadata.json").read_text())
    values, top = affine_values(directory)
    write_rows(directory, "scalar", ((eid, v[1]) for eid, vs in values.items() for v in vs if v[0] == "n"))
    write_rows(directory, "affine_stack", ((eid, v[1], v[2]) for eid, vs in values.items() for v in vs if v[0] == "s"))
    write_rows(directory, "numeric_top", ((eid,) for eid in top))
    functions = [r[0] for r in read_rows(directory, "function")]
    spans = {func: [0, metadata["bits"] // 8] for func in functions}
    accesses = {(func, 0, metadata["bits"] // 8) for func in functions}
    for relation in ("load", "store"):
        for _, func, _, size, address, _ in read_rows(directory, relation):
            for value in values[int(address)]:
                if value[0] == "s":
                    frame, offset = value[1:]
                    accesses.add((frame, offset, int(size)))
                    spans[frame][0] = min(spans[frame][0], offset)
                    spans[frame][1] = max(spans[frame][1], offset + int(size))
    # The block identity denotes the whole frame. Its numeric span describes
    # observed accesses, and is not used to discard unknown-offset pointers.
    write_rows(directory, "stack_access", accesses)
    regions = [(name, int(start), int(end)) for name, start, end in read_rows(directory, "global_region")]
    write_rows(directory, "pointer_seed", ((int(eid), f"stk_{func}") for eid, func in read_rows(directory, "stack_root")))
    names = {name: int(reg) for reg, name in read_rows(directory, "register")}
    inputs = {(int(stmt), int(reg)): int(value) for stmt, reg, value in read_rows(directory, "call_input")}
    outputs = {(int(stmt), int(reg)): int(value) for stmt, reg, value in read_rows(directory, "call_output")}
    externals = {int(addr): name for addr, name in read_rows(directory, "external")}
    allocs, heap, seeds = [], [], []
    for stmt, func, _, site, target, _ in read_rows(directory, "call"):
        stmt, site, target = int(stmt), int(site), int(target)
        targets = {v[1] for v in values[target] if v[0] == "n"}
        for address in targets:
            allocator = externals.get(address)
            if allocator not in {"malloc", "calloc", "realloc"}:
                continue
            size = -1
            if metadata["arch"] == "AMD64":
                def arg(name):
                    eid = inputs.get((stmt, names.get(name)))
                    nums = {v[1] for v in values[eid] if v[0] == "n"} if eid is not None else set()
                    return next(iter(nums)) if len(nums) == 1 else None
                if allocator == "malloc":
                    size = arg("rdi")
                elif allocator == "realloc":
                    size = arg("rsi")
                else:
                    n, item_size = arg("rdi"), arg("rsi")
                    size = n * item_size if n is not None and item_size is not None else None
                size = size if size is not None and 0 < size < 1 << 63 else -1
            block = f"heap_{func}_{site}"
            allocs.append((func, site, allocator, size))
            heap.append((block, func, site, size))
            seeds.append((stmt, outputs[(stmt, metadata["return_reg"])], block))
    write_rows(directory, "heap_alloc_call", allocs)
    write_rows(directory, "heap_result", seeds)
    write_rows(directory, "pointer_width", [(metadata["bits"],)])
    write_rows(directory, "abi_sp", [(metadata["sp"],)])
    write_rows(directory, "abi_return", [(metadata["return_reg"],)])
    first_arg = names.get("rdi", -1)
    write_rows(directory, "abi_first_arg", [(first_arg,)])
    write_rows(directory, "abi_second_arg", [(names.get("rsi", -1),)])
    return {"widened_expressions": len(top), "stack_blocks": len(spans),
            "global_blocks": len(regions), "heap_blocks": len(heap)}
