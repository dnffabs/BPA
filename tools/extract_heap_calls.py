#!/usr/bin/env python3
"""Schema-v2 allocator helper; the normal pipeline uses memory_model.build."""
import argparse
from pathlib import Path
import shutil

from memory_model import build

ALLOC_NAMES = {'malloc', 'calloc', 'realloc'}


def get_plt_addrs(binary_path):
    # CLE handles .plt/.plt.sec, REL/RELA and load bias consistently.
    import angr
    obj = angr.Project(str(binary_path), auto_load_libs=False).loader.main_object
    return {address: name for name, address in obj.plt.items() if name in ALLOC_NAMES}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary')
    parser.add_argument('facts_dir')
    parser.add_argument('-o', '--output', required=True)
    args = parser.parse_args()
    build(Path(args.facts_dir))
    source = Path(args.facts_dir) / 'heap_alloc_call.facts'
    if source.resolve() != Path(args.output).resolve():
        shutil.copyfile(source, args.output)


if __name__ == '__main__':
    main()
