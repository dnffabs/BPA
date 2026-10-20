"""Jump target identities are emitted by VexParser.parse in schema v2.

IRSB.next must pass through VexParser.expr. constant_jump_targets cannot
represent a dynamic target and must not be used as a replacement for it.
"""


def collect_jumpkinds(*args, **kwargs):
    raise RuntimeError('Schema v1 jump facts retired; use VexParser.parse and call.target')
