"""Deterministic TSV facts. IDs share one allocator and explicit namespaces."""
from collections import defaultdict
from pathlib import Path


class DatalogFacts:
    def __init__(self):
        self.rows = defaultdict(set)
        self.ids = {}
        self.next_id = 1

    def eid(self, key):
        if key not in self.ids:
            self.ids[key] = self.next_id
            self.next_id += 1
        return self.ids[key]

    def add(self, relation, *fields):
        self.rows[relation].add(tuple(fields))

    def write_to_file(self, directory, relations=()):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        for name in set(relations) | self.rows.keys():
            lines = ["\t".join(map(str, row)) for row in sorted(self.rows[name], key=str)]
            (directory / f"{name}.facts").write_text("\n".join(lines) + ("\n" if lines else ""))
