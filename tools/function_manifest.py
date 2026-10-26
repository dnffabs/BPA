"""Shared ELF-RVA function boundaries and an independent instruction inventory.

The manifest binds ranges to the exact ELF SHA256. Importing a manifest supplies
boundaries, not recovered semantics; stripped recovery itself is not inferred.
"""
import argparse
import hashlib
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP
from capstone.x86_const import X86_OP_IMM
from elftools.elf.elffile import ELFFile

from gen_compiler_builtin import is_builtin


def number(value):
    return int(value, 16 if value.lower().startswith('0x') else 10) if isinstance(value, str) else int(value)


def elf_info(binary):
    with Path(binary).open('rb') as stream:
        elf = ELFFile(stream)
        loads = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        base = min(int(s['p_vaddr']) for s in loads)
        executable = [(int(s['p_vaddr'])-base, int(s['p_vaddr'])+int(s['p_memsz'])-base)
                      for s in loads if s['p_flags'] & 1]
        return dict(binary_sha256=hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                    bits=elf.elfclass, linked_base=base, executable_ranges=executable,
                    has_symtab=elf.get_section_by_name('.symtab') is not None)


def validate(document, info):
    if document.get('schema') != 1 or document.get('address_space') != 'elf-rva':
        raise ValueError('Function manifest needs schema=1 and address_space=elf-rva')
    if document.get('binary_sha256') != info['binary_sha256']:
        raise ValueError('Function manifest SHA256 does not match this ELF')
    if document.get('bits') != info['bits']:
        raise ValueError('Function manifest architecture width does not match this ELF')
    result, names, starts = [], set(), set()
    for row in document.get('functions', []):
        name, start, end = row['name'], number(row['start']), number(row['end'])
        if not isinstance(name, str) or not name or any(c in name for c in '\t\n\r'):
            raise ValueError('Invalid function name in manifest')
        if name in names or start in starts:
            raise ValueError('Manifest function names and entries must be unique; use aliases for the same entry')
        if start < 0 or end <= start or not any(a <= start < end <= b for a,b in info['executable_ranges']):
            raise ValueError(f'Function range is not inside executable ELF memory: {name}')
        names.add(name)
        starts.add(start)
        result.append(dict(row, name=name, start=start, end=end))
    result.sort(key=lambda r:r['start'])
    if not result:
        raise ValueError('Function manifest has no functions')
    if any(a['end'] > b['start'] for a,b in zip(result,result[1:])):
        raise ValueError('Overlapping function ranges in manifest')
    return result


def select(binary, obj, entry, manifest_path=None):
    info = elf_info(binary)
    if manifest_path:
        document = json.loads(Path(manifest_path).read_text())
        rows = validate(document, info)
        source = 'manifest'
    else:
        if not info['has_symtab']:
            raise ValueError('Input has no .symtab: stripped function recovery is not implemented; supply --functions with verified boundaries')
        by_addr, used_names = {}, set()
        for symbol in sorted(obj.symbols, key=lambda s:(s.rebased_addr,s.name != entry,s.name)):
            if not (symbol.is_function and not symbol.is_import and symbol.size > 0 and not is_builtin(symbol.name)):
                continue
            if symbol.rebased_addr in by_addr:
                by_addr[symbol.rebased_addr]['aliases'].append(symbol.name)
                continue
            name = symbol.name if symbol.name not in used_names else f'{symbol.name}@{symbol.rebased_addr:x}'
            used_names.add(name)
            by_addr[symbol.rebased_addr] = dict(name=name, start=symbol.rebased_addr-obj.mapped_base,
                 end=symbol.rebased_addr-obj.mapped_base+symbol.size, source='elf-symbol', aliases=[])
        document = dict(schema=1,address_space='elf-rva',binary_sha256=info['binary_sha256'],
                        bits=info['bits'],functions=list(by_addr.values()))
        rows = validate(document,info)
        source = 'symbols'
    # An explicit entry alias may select an existing function without renaming
    # its address identity, which is shared with other tools.
    entry_name = next((r['name'] for r in rows if r['name']==entry or entry in r.get('aliases',[])), None)
    if entry_name is None:
        raise ValueError(f'Entry function {entry!r} not found in selected function ranges')
    document = dict(schema=1,address_space='elf-rva',binary_sha256=info['binary_sha256'],bits=info['bits'],
                    entry=entry_name,source=source,functions=rows)
    return document, info


def inventory(binary, document):
    """Linear decode only within the common ranges; record gaps explicitly."""
    sites, gaps = [], []
    with Path(binary).open('rb') as stream:
        elf = ELFFile(stream)
        loads = [s for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
        base = min(int(s['p_vaddr']) for s in loads)
        decoder = Cs(CS_ARCH_X86, CS_MODE_64 if elf.elfclass==64 else CS_MODE_32)
        decoder.detail = True
        for row in document['functions']:
            start, end = row['start']+base, row['end']+base
            segment = next((s for s in loads if int(s['p_vaddr']) <= start < int(s['p_vaddr'])+int(s['p_filesz'])),None)
            if segment is None:
                gaps.append(dict(function=row['name'],start=row['start'],bytes=end-start))
                continue
            offset = start-int(segment['p_vaddr'])
            data = segment.data()[offset:offset+end-start]
            decoded_end = start
            for instruction in decoder.disasm(data,start):
                decoded_end = instruction.address+instruction.size
                if not (instruction.group(CS_GRP_CALL) or instruction.group(CS_GRP_JUMP)):
                    continue
                direct = bool(instruction.operands and instruction.operands[0].type==X86_OP_IMM)
                sites.append(dict(function=row['name'],rva=instruction.address-base,
                    kind='call' if instruction.group(CS_GRP_CALL) else 'jump',indirect=not direct,
                    target_rva=instruction.operands[0].imm-base if direct else None,
                    assembly=instruction.mnemonic+' '+instruction.op_str))
            if decoded_end < end:
                gaps.append(dict(function=row['name'],start=decoded_end-base,bytes=end-decoded_end))
    return dict(schema=1,address_space='elf-rva',binary_sha256=document['binary_sha256'],sites=sites,decode_gaps=gaps,
                scope='CALL and JUMP instructions independently decoded inside shared function ranges; tail classification comes separately')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary')
    parser.add_argument('--from-bpax',required=True,help='user_defined_addr_func.facts, in mapped virtual addresses')
    parser.add_argument('--mapped-base',required=True,type=lambda s:int(s,0))
    parser.add_argument('--output',required=True)
    parser.add_argument('--entry',default='main')
    args = parser.parse_args()
    info = elf_info(args.binary)
    rows, excluded = [], []
    for line in Path(args.from_bpax).read_text().splitlines():
        if not line:
            continue
        name,start,end = line.split('\t')
        start,end = int(start)-args.mapped_base,int(end)-args.mapped_base
        if is_builtin(name) or not any(a <= start < end <= b for a,b in info['executable_ranges']):
            excluded.append(name)
            continue
        rows.append(dict(name=name,start=start,end=end,source='bpa-x-facts'))
    # Names are presentation labels; retain distinct addresses with suffixes.
    unique, names = {}, set()
    for row in sorted(rows,key=lambda r:r['start']):
        if row['start'] in unique:
            unique[row['start']].setdefault('aliases',[]).append(row['name'])
            continue
        if row['name'] in names:
            row['name'] += f"@{row['start']:x}"
        names.add(row['name'])
        unique[row['start']] = row
    document = dict(schema=1,address_space='elf-rva',binary_sha256=info['binary_sha256'],bits=info['bits'],
                    entry=args.entry,source='bpa-x-facts',functions=list(unique.values()),excluded=excluded)
    validate(document,info)
    Path(args.output).write_text(json.dumps(document,indent=2)+'\n')


if __name__=='__main__':
    main()
