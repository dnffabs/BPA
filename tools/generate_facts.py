#!/usr/bin/env python3
"""Extract normalized facts using one consistent angr project and CFG."""
import argparse
import json
from bisect import bisect_right
from pathlib import Path

import angr
from vex2Datalog.DatalogFacts import DatalogFacts
from vex2Datalog.parser import VexParser
from function_manifest import select, inventory
from control_flow import classify

INPUTS = ("function", "block", "edge", "entry_reg", "register", "statement", "temporary",
          "reg_def", "reg_read", "copy", "constant", "binary", "unary", "load", "store",
          "call", "call_input", "call_output", "return_block", "global_region", "global_word",
          "external", "root", "stack_root", "unknown_seed", "unsupported", "call_stack",
          "constant_origin", "address_taken", "external_address_taken", "analysis_root", "root_reason",
          "tail_call", "tail_candidate", "call_kind", "tail_evidence")
GENERAL = {"AMD64": ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
                     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
           "X86": ("eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp")}
CLOBBERED = {"AMD64": ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"),
             "X86": ("eax", "ecx", "edx")}


def generate(binary_path, output_dir, entry="main", functions_path=None, roots="main"):
    binary_path, output_dir = Path(binary_path).resolve(), Path(output_dir)
    if roots not in ('main','main-and-at'):
        raise ValueError(f'Unknown root policy: {roots}')
    project = angr.Project(str(binary_path), auto_load_libs=False)
    arch, obj = project.arch, project.loader.main_object
    if arch.name not in GENERAL:
        raise ValueError(f"Unsupported architecture {arch.name}; baseline supports Linux AMD64/X86")
    manifest, elf_metadata = select(binary_path,obj,entry,functions_path)
    cfg = project.analyses.CFGFast(normalize=True,detect_tail_calls=False,
            function_starts=[r['start']+obj.mapped_base for r in manifest['functions']])
    facts = DatalogFacts()
    functions, names = {}, {}
    for row in manifest['functions']:
        start,end = row['start']+obj.mapped_base,row['end']+obj.mapped_base
        name = row['name']
        names[name] = start
        functions[start] = (name,end-start)
        facts.add('function',name,start,end)
    facts.add("root", manifest['entry'])
    facts.add('root_reason',manifest['entry'],'entry')
    for name, address in sorted(obj.plt.items()):
        facts.add("external", address, name.split("@")[0])
    parser = VexParser(facts, arch)
    nodes = {}
    starts = sorted(functions)
    for node in cfg.graph.nodes():
        index = bisect_right(starts,node.addr)-1
        if index < 0:
            continue
        start = starts[index]
        name,size = functions[start]
        if not start <= node.addr < start+size or node.block is None:
            continue
        block = node.block
        if block.size > start+size-node.addr:
            block = project.factory.block(node.addr,size=start+size-node.addr)
        if not block.instruction_addrs:
            continue
        nodes[node.addr] = (name,block)
        facts.add('block',name,node.addr,int(node.addr==start))
    calls = []
    for address, (name, block) in sorted(nodes.items()):
        start = names[name]
        kind,evidence = classify(block,start,start+functions[start][1],functions,set(obj.plt.values()),cfg)
        result = parser.parse(block, name,kind,evidence)
        if result:
            call_stmt, order = result
            calls.append((call_stmt, name, address, block.instruction_addrs[-1], order,kind))
    for source, destination, data in cfg.graph.edges(data=True):
        if source.addr in nodes and destination.addr in nodes and nodes[source.addr][0] == nodes[destination.addr][0]:
            kind = data.get("jumpkind", "Ijk_Boring")
            if kind not in ("Ijk_Call", "Ijk_Ret"):
                facts.add("edge", nodes[source.addr][0], source.addr, destination.addr, kind)
    locations = {row[0] for row in facts.rows["register"]}
    general = {arch.registers[name][0] for name in GENERAL[arch.name]}
    for _, (name, _) in functions.items():
        for loc in sorted(locations | general):
            version = facts.eid(("entry", name, loc))
            facts.add("entry_reg", name, loc, version)
            if loc == arch.sp_offset:
                facts.add("stack_root", version, name)
    captured_stack = {row[0] for row in facts.rows["call_stack"]}
    for call_stmt, name, bb, address, order,kind in calls:
        # Snapshot SP before CALL's hardware return-address push. It is a
        # coordinate for stack arguments, not a register actual/formal edge.
        if call_stmt not in captured_stack:
            stack_snapshot = facts.eid(("call_stack", call_stmt))
            facts.add("reg_read", call_stmt, name, bb, order + 1, arch.sp_offset, stack_snapshot)
            facts.add("call_stack", call_stmt, stack_snapshot)
        for loc in sorted(general - {arch.sp_offset}):
            snapshot = facts.eid(("argument", call_stmt, loc))
            facts.add("reg_read", call_stmt, name, bb, order + 1, loc, snapshot)
            facts.add("call_input", call_stmt, loc, snapshot)
        for index, reg in enumerate(CLOBBERED[arch.name], 1):
            loc = arch.registers[reg][0]
            if kind in ('tail','tail-candidate'):
                value = facts.eid(('tail_result',call_stmt,loc))
                facts.add('call_output',call_stmt,loc,value)
                continue
            virtual_stmt = facts.eid(("clobber", call_stmt, loc))
            value = facts.eid(("return", call_stmt, loc))
            version = facts.eid(("definition", virtual_stmt, loc))
            facts.add("statement", virtual_stmt, name, bb, address, order + 2 + index)
            facts.add("reg_def", virtual_stmt, name, bb, order + 2 + index, loc, value, version)
            facts.add("copy", value, version)
            facts.add("call_output", call_stmt, loc, value)
    # CLE memory contains relocated initial values, including PIE addresses.
    section_names = {".data", ".bss", ".rodata", ".data.rel.ro", ".sdata", ".sbss", ".got", ".got.plt"}
    word = arch.bytes
    for section in obj.sections:
        if section.name not in section_names or not section.memsize:
            continue
        start, end = section.vaddr, section.vaddr + section.memsize
        facts.add("global_region", section.name, start, end)
        if section.name in {".bss", ".sbss"}:
            continue
        for address in range(start, end - word + 1, word):
            raw = project.loader.memory.load(address, word)
            value = int.from_bytes(raw, "little" if arch.memory_endness == "Iend_LE" else "big")
            if value < (1 << 63):
                facts.add("global_word", address, value)
    constants = {eid:value for eid,_,value in facts.rows['constant']}
    external = {address:name for address,name in facts.rows['external']}
    evidence_rows = [(constants[eid],'instruction',address) for eid,_,address in facts.rows['constant_origin']]
    evidence_rows += [(value,'global',address) for address,value in facts.rows['global_word']]
    for value,source,address in evidence_rows:
        if value in functions:
            name = functions[value][0]
            facts.add('address_taken',name,source,address)
            if roots == 'main-and-at':
                facts.add('analysis_root',name)
                facts.add('root_reason',name,'address-taken')
        if value in external:
            facts.add('external_address_taken',value,source,address)
    output_dir.mkdir(parents=True,exist_ok=True)
    (output_dir/'functions.json').write_text(json.dumps(manifest,indent=2)+'\n')
    catalog = inventory(binary_path,manifest)
    lifted = {pc for _,block in nodes.values() for pc in block.instruction_addrs}
    for site in catalog['sites']:
        site['instruction_lifted'] = site['rva']+obj.mapped_base in lifted
    (output_dir/'instruction_inventory.json').write_text(json.dumps(catalog,indent=2)+'\n')
    facts.write_to_file(output_dir, INPUTS)
    metadata = {"schema": 2, "binary": str(binary_path), "arch": arch.name, "bits": arch.bits,
                "sp": arch.sp_offset, "bp": arch.bp_offset, "return_reg": arch.ret_offset,
                "entry": manifest['entry'], "mapped_base": obj.mapped_base, "linked_base": obj.linked_base,
                "blocks": len(nodes), "functions": len(functions), 'control_schema':1,
                'root_policy':roots,'function_source':manifest['source'],'function_manifest':str(Path(functions_path).resolve()) if functions_path else None,
                'binary_sha256':elf_metadata['binary_sha256'],
                'functions_without_entry_block':[name for start,(name,_) in functions.items() if start not in nodes]}
    (output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    return metadata


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary_path")
    p.add_argument("-o", "--output", default="output")
    p.add_argument("--entry", default="main")
    p.add_argument('--functions',help='shared schema-1 ELF-RVA function manifest')
    p.add_argument('--roots',choices=('main','main-and-at'),default='main')
    args = p.parse_args()
    print(json.dumps(generate(args.binary_path, args.output, args.entry,args.functions,args.roots)))


if __name__ == "__main__":
    main()
