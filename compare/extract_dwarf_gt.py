#!/usr/bin/env python3
"""Extract variable GT into an explicit output directory (entry-SP basis)."""
import argparse
import json
from pathlib import Path
import re

from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_DWARF_expr, set_global_machine_arch
from elftools.dwarf.locationlists import LocationEntry, LocationExpr, LocationParser


def get_var_size(die, CU=None, seen=None):
    seen = set() if seen is None else set(seen)
    if die.offset in seen:
        return 0
    seen.add(die.offset)
    size = die.attributes.get('DW_AT_byte_size')
    if size is not None:
        return size.value
    if die.tag == 'DW_TAG_pointer_type':
        return die.cu['address_size']
    if die.tag == 'DW_TAG_array_type':
        if 'DW_AT_type' not in die.attributes:
            return 0
        result = get_var_size(die.get_DIE_from_attribute('DW_AT_type'), seen=seen)
        dimensions = 0
        for child in die.iter_children():
            if child.tag != 'DW_TAG_subrange_type':
                continue
            count = child.attributes.get('DW_AT_count')
            upper = child.attributes.get('DW_AT_upper_bound')
            lower = child.attributes.get('DW_AT_lower_bound')
            if count is not None and isinstance(count.value, int):
                n = count.value
            elif upper is not None and isinstance(upper.value, int):
                n = upper.value - (lower.value if lower else 0) + 1
            else:
                return 0
            result *= max(n, 0)
            dimensions += 1
        return result if dimensions else 0
    if 'DW_AT_type' in die.attributes:
        try:
            return get_var_size(die.get_DIE_from_attribute('DW_AT_type'), seen=seen)
        except (KeyError, NotImplementedError):
            return 0
    return 0


def parse_loc_expr(text):
    match = re.search(r'DW_OP_fbreg:\s*(-?\d+)', text)
    if match:
        return 'DW_OP_fbreg', int(match[1])
    match = re.search(r'DW_OP_addr:\s*(?:0x)?([0-9a-fA-F]+)', text)
    if match:
        return 'DW_OP_addr', int(match[1], 16)
    return None, None


def locations(die, parser, dwarf, cu):
    attr = die.attributes.get('DW_AT_location')
    if attr is None or not parser.attribute_has_location(attr, cu['version']):
        return []
    try:
        location = parser.parse_from_attribute(attr, cu['version'], die)
    except (KeyError, NotImplementedError):
        return []
    exprs = [location.loc_expr] if isinstance(location, LocationExpr) else [x.loc_expr for x in location if isinstance(x, LocationEntry)]
    return [describe_DWARF_expr(expr, dwarf.structs, cu.cu_offset) for expr in exprs]


def process(binary_path, output_dir='.', load_bias=0):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    local_rows, global_rows, skipped = set(), set(), 0
    with open(binary_path, 'rb') as stream:
        elf = ELFFile(stream)
        has_debug = any(elf.get_section_by_name(name) is not None
                        for name in ('.debug_info', '.zdebug_info'))
        if has_debug:
            set_global_machine_arch(elf.get_machine_arch())
            dwarf = elf.get_dwarf_info()
            parser = LocationParser(dwarf.location_lists())
            ptr = elf.elfclass // 8

            def walk(die, cu, function=None, cfa_frame=False):
                nonlocal skipped
                if die.tag == 'DW_TAG_subprogram':
                    attr = die.attributes.get('DW_AT_name')
                    function = attr.value.decode(errors='replace') if attr and isinstance(attr.value, bytes) else None
                    base = die.attributes.get('DW_AT_frame_base')
                    cfa_frame = bool(base and base.form == 'DW_FORM_exprloc' and
                                     list(base.value) == [0x9c])
                if die.tag in ('DW_TAG_variable', 'DW_TAG_formal_parameter'):
                    size = get_var_size(die, cu)
                    matched = False
                    for text in locations(die, parser, dwarf, cu):
                        kind, value = parse_loc_expr(text)
                        if size and kind == 'DW_OP_addr':
                            global_rows.add((value + load_bias, size))
                            matched = True
                        elif size and function and cfa_frame and kind == 'DW_OP_fbreg':
                            # CFA at function entry is entry-SP + return-address size.
                            local_rows.add((function, value + ptr, size))
                            matched = True
                    if not matched and 'DW_AT_location' in die.attributes:
                        skipped += 1
                for child in die.iter_children():
                    walk(child, cu, function, cfa_frame)

            for cu in dwarf.iter_CUs():
                walk(cu.get_top_DIE(), cu)
    for name, data in [('stack_gt.tsv', local_rows), ('global_gt.tsv', global_rows)]:
        (output_dir / name).write_text(''.join('\t'.join(map(str, row))+'\n' for row in sorted(data)))
    metadata = {'has_dwarf': has_debug, 'stack_reference': 'function entry SP',
                'stack_entries': len(local_rows), 'global_entries': len(global_rows),
                'skipped_locations': skipped, 'load_bias': load_bias}
    (output_dir / 'gt_metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
    return metadata


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary')
    parser.add_argument('--output-dir', default='.')
    args = parser.parse_args()
    print(json.dumps(process(args.binary, args.output_dir)))
