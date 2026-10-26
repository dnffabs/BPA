"""Transfer classification and certified indirect-tail candidate promotion."""
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM


def classify(block, function_start, function_end, function_entries, external_entries, cfg):
    if block.vex.jumpkind == 'Ijk_Call':
        return 'call', 'machine-call'
    if block.vex.jumpkind != 'Ijk_Boring' or not block.capstone.insns:
        return None, None
    insn = block.capstone.insns[-1].insn
    if not insn.mnemonic.endswith(('jmp','ljmp')) or not insn.operands:
        return None, None
    operand = insn.operands[0]
    if operand.type == X86_OP_IMM:
        if operand.imm in external_entries or (operand.imm in function_entries and operand.imm != function_start):
            return 'tail', 'direct-function-entry'
        return None, None
    if block.addr in cfg.jump_tables or insn.address in cfg.jump_tables:
        return None, 'jump-table'
    if operand.type == X86_OP_MEM and operand.mem.index:
        return None, 'indexed-indirect-jump'
    node = cfg.model.get_any_node(block.addr)
    if node is not None and any(function_start <= successor.addr < function_end for successor in cfg.graph.successors(node)):
        return None, 'intra-function-jump'
    # Promotion additionally needs a complete entry-SP identity. Without it,
    # this remains an explicit unconfirmed jump, not a resolved tail call.
    return 'tail-candidate', 'unresolved-nonindexed-jump'


def promote(directory, values, complete):
    from pathlib import Path
    from memory_model import read_rows, write_rows
    if not (Path(directory)/'tail_candidate.facts').exists():
        return 0  # legacy scalar/affine-only facts, without control extension
    candidates = read_rows(directory, 'tail_candidate')
    if not candidates:
        return 0
    stack = {int(s):int(e) for s,e in read_rows(directory,'call_stack')}
    calls = read_rows(directory,'call')
    tails = read_rows(directory,'tail_call')
    kinds = {int(s):k for s,k in read_rows(directory,'call_kind')}
    evidence = read_rows(directory,'tail_evidence')
    unsupported = [r for r in read_rows(directory,'unsupported') if not r[-1].startswith('unconfirmed tail candidate')]
    promoted = 0
    existing = {int(row[0]) for row in calls}
    for row in candidates:
        stmt,func,_,addr,_,_ = row
        stmt = int(stmt)
        if stmt in existing:
            continue
        expression = stack.get(stmt)
        alternatives = values.get(expression,set())
        if expression in complete and alternatives == {('s',func,0)}:
            calls.append(row)
            tails.append((stmt,))
            kinds[stmt] = 'tail'
            evidence.append((stmt,'indirect-restored-entry-sp'))
            promoted += 1
        else:
            unsupported.append((func,addr,'unconfirmed tail candidate: entry SP not certified'))
    write_rows(directory,'call',(tuple(r) for r in calls))
    write_rows(directory,'tail_call',(tuple(r) for r in tails))
    write_rows(directory,'call_kind',kinds.items())
    write_rows(directory,'tail_evidence',(tuple(r) for r in evidence))
    write_rows(directory,'unsupported',(tuple(r) for r in unsupported))
    return promoted
