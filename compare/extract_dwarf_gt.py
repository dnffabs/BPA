#!/usr/bin/env python3
"""
Extract DWARF ground-truth for local and global variables.

Local output  (stack_gt.tsv):  func_name  offset  size
Global output (global_gt.tsv): abs_addr   size

Usage:
    python extract_dwarf_gt.py <binary>
"""
import sys
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_DWARF_expr, set_global_machine_arch
from elftools.dwarf.locationlists import LocationEntry, LocationExpr, LocationParser


def get_var_size(die, CU):
    """Recursively resolve byte size of a variable's type."""
    type_attr = die.attributes.get('DW_AT_type')
    if not type_attr:
        bs = die.attributes.get('DW_AT_byte_size')
        return bs.value if bs else 0
    try:
        type_die = CU.get_DIE_from_refaddr(type_attr.value + CU.cu_offset)
    except Exception:
        return 0
    if type_die.tag == 'DW_TAG_array_type':
        # product of subrange counts * element size
        counts = []
        for child in type_die.iter_children():
            if child.tag == 'DW_TAG_subrange_type':
                ub = child.attributes.get('DW_AT_upper_bound')
                lb = child.attributes.get('DW_AT_lower_bound')
                ub = ub.value if ub else 0
                lb = lb.value if lb else 0
                counts.append(ub - lb + 1)
        elem_size = get_var_size(type_die, CU)
        mul = 1
        for c in counts:
            mul *= c
        return mul * elem_size
    return get_var_size(type_die, CU)


def parse_loc_expr(loc_expr_str):
    """Return (register_hint, offset) from a DWARF expression string."""
    s = loc_expr_str.replace('(', '').replace(')', '').replace(' ', '')
    for reg in ('DW_OP_fbreg', 'rbp', 'ebp', 'DW_OP_addr'):
        if reg in s:
            parts = s.split(':')
            val = parts[1].strip() if len(parts) > 1 else '0'
            try:
                # DW_OP_addr values are bare hex (no 0x prefix); fbreg/rbp/ebp are decimal
                if reg == 'DW_OP_addr':
                    num = int(val, 16)
                else:
                    num = int(val)
            except ValueError:
                num = 0
            return reg, num
    return None, None


def extract_local_offset(die, loc_parser, location_lists, dwarfinfo, CU, arch):
    """Return (offset, size) matching stack_boundary.dl's reference point.

    stack_boundary.dl uses fbreg-relative offsets directly (CFA-relative).
    - DW_OP_fbreg: use value as-is
    - rbp/ebp-relative: add ptr_size to convert to same basis
        x86: ebp_val + 4  (ebp = CFA - 8, fbreg base = CFA - 4, diff = +4)
        x64: rbp_val + 8
    """
    is64 = arch in ('x64', 'AMD64')
    ptr = 8 if is64 else 4

    size = get_var_size(die, CU)
    if size == 0:
        return None
    for attr in die.attributes.values():
        if not loc_parser.attribute_has_location(attr, CU['version']):
            continue
        loc = loc_parser.parse_from_attribute(attr, CU['version'], die)
        exprs = []
        if isinstance(loc, LocationExpr):
            exprs = [describe_DWARF_expr(loc.loc_expr, dwarfinfo.structs, CU.cu_offset)]
        elif isinstance(loc, list):
            exprs = [describe_DWARF_expr(e.loc_expr, dwarfinfo.structs, CU.cu_offset)
                     for e in loc if isinstance(e, LocationEntry)]
        for expr_str in exprs:
            reg, val = parse_loc_expr(expr_str)
            if val is None:
                continue
            if reg == 'DW_OP_fbreg':
                return val, size
            if reg in ('rbp', 'ebp'):
                return val + ptr, size
    return None


def extract_global_addr(die, loc_parser, location_lists, dwarfinfo, CU):
    """Return (abs_addr, size) for a global variable DIE, or None."""
    size = get_var_size(die, CU)
    if size == 0:
        return None
    for attr in die.attributes.values():
        if not loc_parser.attribute_has_location(attr, CU['version']):
            continue
        loc = loc_parser.parse_from_attribute(attr, CU['version'], die)
        exprs = []
        if isinstance(loc, LocationExpr):
            exprs = [describe_DWARF_expr(loc.loc_expr, dwarfinfo.structs, CU.cu_offset)]
        elif isinstance(loc, list):
            exprs = [describe_DWARF_expr(e.loc_expr, dwarfinfo.structs, CU.cu_offset)
                     for e in loc if isinstance(e, LocationEntry)]
        for expr_str in exprs:
            reg, val = parse_loc_expr(expr_str)
            if reg == 'DW_OP_addr' and val is not None and val != 0:
                return val, size
    return None


def walk_globals(die, loc_parser, location_lists, dwarfinfo, CU, results):
    """Recursively collect global variables from all DIE levels."""
    for child in die.iter_children():
        if child.tag == 'DW_TAG_variable':
            decl = child.attributes.get('DW_AT_declaration')
            if decl and decl.value:
                continue
            name_attr = child.attributes.get('DW_AT_name')
            if name_attr:
                r = extract_global_addr(child, loc_parser, location_lists, dwarfinfo, CU)
                if r:
                    results.append(r)
        # recurse into namespaces, classes, etc.
        elif child.tag not in ('DW_TAG_subprogram', 'DW_TAG_lexical_block'):
            walk_globals(child, loc_parser, location_lists, dwarfinfo, CU, results)


def walk_locals(die, func_name, loc_parser, location_lists, dwarfinfo, CU, arch, results):
    for child in die.iter_children():
        if child.tag in ('DW_TAG_variable', 'DW_TAG_formal_parameter'):
            r = extract_local_offset(child, loc_parser, location_lists, dwarfinfo, CU, arch)
            if r:
                results.append((func_name, r[0], r[1]))
        if child.tag in ('DW_TAG_lexical_block', 'DW_TAG_inlined_subroutine'):
            walk_locals(child, func_name, loc_parser, location_lists, dwarfinfo, CU, arch, results)


def process(binary_path):
    local_rows = []   # (func_name, offset, size)
    global_rows = []  # (abs_addr, size)

    with open(binary_path, 'rb') as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            print("No DWARF info found.")
            return
        arch = elf.get_machine_arch()
        set_global_machine_arch(arch)
        dwarfinfo = elf.get_dwarf_info()
        location_lists = dwarfinfo.location_lists()
        loc_parser = LocationParser(location_lists)

        for CU in dwarfinfo.iter_CUs():
            top = CU.get_top_DIE()
            # Global variables: walk all DIE levels
            walk_globals(top, loc_parser, location_lists, dwarfinfo, CU, global_rows)

            # Functions → local variables
            for die in top.iter_children():
                if die.tag == 'DW_TAG_subprogram':
                    name_attr = die.attributes.get('DW_AT_name')
                    decl = die.attributes.get('DW_AT_declaration')
                    if name_attr and not (decl and decl.value):
                        func_name = name_attr.value
                        if isinstance(func_name, bytes):
                            func_name = func_name.decode('utf-8', errors='replace')
                        walk_locals(die, func_name, loc_parser, location_lists, dwarfinfo, CU, arch, local_rows)

    # Write stack_gt.tsv
    with open('stack_gt.tsv', 'w') as f:
        for func, offset, size in local_rows:
            f.write(f"{func}\t{offset}\t{size}\n")
    print(f"stack_gt.tsv: {len(local_rows)} entries")

    # Write global_gt.tsv
    with open('global_gt.tsv', 'w') as f:
        for addr, size in global_rows:
            f.write(f"{addr}\t{size}\n")
    print(f"global_gt.tsv: {len(global_rows)} entries")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python extract_dwarf_gt.py <binary>")
        sys.exit(1)
    process(sys.argv[1])
