#!/usr/bin/env python3
"""Compatibility CLI: generate schema-v2 facts using the unified extractor."""
import argparse
from generate_facts import generate


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary')
    p.add_argument('facts_dir')
    a = p.parse_args()
    generate(a.binary, a.facts_dir)
