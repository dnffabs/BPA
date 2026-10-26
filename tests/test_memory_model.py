"""Bit-width and displacement tests for the affine stack prepass."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from memory_model import affine_values, build, read_rows, write_rows


class StackDisplacements(unittest.TestCase):
    def fixture(self, bits, **relations):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name)
        inputs = ("copy", "def_use", "binary", "unary", "constant", "stack_root",
                  "function", "load", "store", "global_region", "register",
                  "call_input", "call_output", "external", "call",
                  "unknown_seed", "entry_reg", "call_stack", "statement", "block", "edge")
        for name in inputs:
            write_rows(path, name, relations.get(name, []))
        (path / "metadata.json").write_text(json.dumps({
            "bits": bits, "arch": "X86" if bits == 32 else "AMD64",
            "sp": 24 if bits == 32 else 48, "return_reg": 8 if bits == 32 else 16,
        }))
        return path

    def test_negative_immediate_and_high_address_remain_distinct(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                path = self.fixture(bits,
                    stack_root=[(1, "main")],
                    constant=[(2, bits, (1 << bits) - 4), (3, 32, 0xF0000000),
                              (4, 32, 4)],
                    binary=[(10, f"Add{bits}", bits, 1, 2),
                            (11, f"Add{bits}", bits, 2, 1),
                            (12, f"Sub{bits}", bits, 1, 2),
                            (13, "Add32", 32, 3, 4)])
                values, top = affine_values(path)
                self.assertEqual(values[10], {("s", "main", -4)})
                self.assertEqual(values[11], {("s", "main", -4)})
                self.assertEqual(values[12], {("s", "main", 4)})
                self.assertEqual(values[3], {("n", 0xF0000000)})
                self.assertEqual(values[13], {("n", 0xF0000004)})
                expected_number = 0xFFFFFFFC if bits == 32 else -4
                self.assertEqual(values[2], {("n", expected_number)})
                self.assertFalse(top)

    def test_chained_arithmetic_wraps_at_operation_width(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                path = self.fixture(bits,
                    stack_root=[(1, "main")],
                    constant=[(2, bits, (1 << bits) - 4), (3, bits, 8),
                              (4, bits, (1 << (bits - 1)) - 1), (5, bits, 1)],
                    binary=[(10, f"Add{bits}", bits, 1, 2),
                            (11, f"Add{bits}", bits, 10, 2),
                            (12, f"Add{bits}", bits, 11, 3),
                            (13, f"Add{bits}", bits, 1, 4),
                            (14, f"Add{bits}", bits, 13, 5),
                            (15, f"Sub{bits}", bits, 14, 5)])
                values, top = affine_values(path)
                self.assertEqual(values[11], {("s", "main", -8)})
                self.assertEqual(values[12], {("s", "main", 0)})
                self.assertEqual(values[14], {("s", "main", -(1 << (bits - 1)))})
                self.assertEqual(values[15], {("s", "main", (1 << (bits - 1)) - 1)})
                self.assertFalse(top)

    def test_numeric_width_conversions_preserve_signedness(self):
        path = self.fixture(64,
            stack_root=[(1, "main")], constant=[(2, 32, 0xFFFFFFFC), (3, 64, -4)],
            unary=[(10, "32Sto64", 64, 2), (11, "32Uto64", 64, 2),
                   (12, "64to32", 32, 3)],
            binary=[(20, "Add64", 64, 1, 10), (21, "Add64", 64, 1, 11),
                    (22, "Add32", 32, 1, 12)])
        values, top = affine_values(path)
        self.assertEqual(values[10], {("n", -4)})
        self.assertEqual(values[11], {("n", 0xFFFFFFFC)})
        self.assertEqual(values[12], {("n", 0xFFFFFFFC)})
        self.assertEqual(values[20], {("s", "main", -4)})
        self.assertEqual(values[21], {("s", "main", 0xFFFFFFFC)})
        self.assertEqual(values[22], {("s", "main", -4)})
        self.assertFalse(top)

    def test_unknown_alignment_and_pointer_truncation_do_not_invent_offsets(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                path = self.fixture(bits,
                    stack_root=[(1, "main")],
                    constant=[(2, bits, (1 << bits) - 16),
                              (3, bits, (1 << bits) - 1), (4, bits, 4)],
                    binary=[(10, f"And{bits}", bits, 1, 2),
                            (11, f"And{bits}", bits, 1, 3),
                            (12, f"Add{bits}", bits, 10, 4)],
                    unary=[(13, f"{bits}to16", 16, 1)])
                values, top = affine_values(path)
                self.assertEqual(values[11], {("s", "main", 0)})
                for eid in (10, 12, 13):
                    self.assertIn(eid, top)
                    self.assertFalse(values[eid])

    def test_build_does_not_emit_four_gib_stack_access(self):
        path = self.fixture(32,
            function=[("main", 0x8049000, 0x8049100)], stack_root=[(1, "main")],
            constant=[(2, 32, 0xFFFFFFFC), (3, 32, 4), (4, 32, 0xF0000000)],
            binary=[(10, "Add32", 32, 1, 2), (11, "Add32", 32, 10, 3)],
            store=[(20, "main", 0x8049010, 4, 10, 4)],
            load=[(21, "main", 0x8049020, 4, 11, 22)])
        build(path)
        self.assertEqual({tuple(row) for row in read_rows(path, "stack_access")},
                         {("main", "-4", "4"), ("main", "0", "4")})
        self.assertIn(["4", str(0xF0000000)], read_rows(path, "scalar"))


if __name__ == "__main__":
    unittest.main()
