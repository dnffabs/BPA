#!/usr/bin/env python3
"""Extract normalized facts using one consistent angr project and CFG."""
import argparse
import json
from pathlib import Path

import angr
from elftools.elf.elffile import ELFFile

from gen_compiler_builtin import is_builtin
from vex2Datalog.DatalogFacts import DatalogFacts
from vex2Datalog.parser import VexParser

INPUTS = ("function", "block", "edge", "entry_reg", "register", "statement", "temporary",
          "reg_def", "reg_read", "copy", "constant", "binary", "unary", "load", "store",
          "call", "call_input", "call_output", "return_block", "global_region", "global_word",
          "external", "root", "stack_root", "unknown_seed", "unsupported", "call_stack")
GENERAL = {"AMD64": ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
                     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
           "X86": ("eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp")}
CLOBBERED = {"AMD64": ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"),
             "X86": ("eax", "ecx", "edx")}


def generate(binary_path, output_dir, entry="main"):
    binary_path, output_dir = Path(binary_path).resolve(), Path(output_dir)
    with binary_path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.get_section_by_name(".symtab") is None:
            raise ValueError("Input has no .symtab: stripped function recovery is not implemented")
    project = angr.Project(str(binary_path), auto_load_libs=False)
    arch, obj = project.arch, project.loader.main_object
    if arch.name not in GENERAL:
        raise ValueError(f"Unsupported architecture {arch.name}; baseline supports Linux AMD64/X86")
    cfg = project.analyses.CFGFast(normalize=True)
    facts = DatalogFacts()
    functions, names = {}, {}
    for symbol in sorted(obj.symbols, key=lambda s: (s.rebased_addr, s.name != entry, s.name)):
        if (symbol.is_function and not symbol.is_import and symbol.size > 0
                and not is_builtin(symbol.name) and symbol.rebased_addr not in functions):
            name = symbol.name
            if name in names:
                name = f"{name}@{symbol.rebased_addr:x}"
            names[name] = symbol.rebased_addr
            functions[symbol.rebased_addr] = (name, symbol.size)
            facts.add("function", name, symbol.rebased_addr, symbol.rebased_addr + symbol.size)
    if entry not in names:
        raise ValueError(f"Entry function {entry!r} not found in defined ELF function symbols")
    facts.add("root", entry)
    for name, address in sorted(obj.plt.items()):
        facts.add("external", address, name.split("@")[0])
    parser = VexParser(facts, arch)
    nodes = {}
    for start, (name, size) in functions.items():
        function = cfg.kb.functions.get(start)
        if function is None:
            raise ValueError(f"CFG has no body for function {name} at {start:#x}")
        for address in sorted(function.block_addrs_set):
            node = cfg.model.get_any_node(address)
            if node and node.block and start <= address < start + size:
                nodes[address] = (name, node.block)
                facts.add("block", name, address, int(address == start))
    calls = []
    for address, (name, block) in sorted(nodes.items()):
        result = parser.parse(block, name)
        if result:
            call_stmt, order = result
            calls.append((call_stmt, name, address, block.instruction_addrs[-1], order))
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
    for call_stmt, name, bb, address, order in calls:
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
    facts.write_to_file(output_dir, INPUTS)
    metadata = {"schema": 2, "binary": str(binary_path), "arch": arch.name, "bits": arch.bits,
                "sp": arch.sp_offset, "bp": arch.bp_offset, "return_reg": arch.ret_offset,
                "entry": entry, "mapped_base": obj.mapped_base, "linked_base": obj.linked_base,
                "blocks": len(nodes), "functions": len(functions)}
    (output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    return metadata


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary_path")
    p.add_argument("-o", "--output", default="output")
    p.add_argument("--entry", default="main")
    args = p.parse_args()
    print(json.dumps(generate(args.binary_path, args.output, args.entry)))


if __name__ == "__main__":
    main()
