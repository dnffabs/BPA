"""VEX -> schema v2; see docs/FACTS.md for column contracts."""
import pyvex


class VexParser:
    def __init__(self, facts, arch):
        self.facts = facts
        self.arch = arch
        self.bb = self.stmt = self.order = self.address = 0
        self.func = ""
        self.irsb = None
        self.expression_counter = 0

    def tmp(self, number):
        eid = self.facts.eid(("tmp", self.bb, number))
        self.facts.add("temporary", eid, self.bb, number)
        return eid

    def fresh(self):
        self.expression_counter += 1
        return self.facts.eid(("expr", self.bb, self.order, self.expression_counter))

    def reg(self, offset, size):
        base = self.arch.get_base_register(offset, max(size, 1))
        loc, full_size = base if base is not None else (offset, size)
        self.facts.add("register", loc, self.arch.translate_register_name(loc, full_size))
        return loc, full_size

    def unknown(self, eid, reason):
        self.facts.add("unknown_seed", eid)
        self.facts.add("unsupported", self.func, self.address, reason)
        return eid

    def expr(self, expr):
        if isinstance(expr, pyvex.expr.RdTmp):
            return self.tmp(expr.tmp)
        eid = self.fresh()
        tag = expr.tag
        bits = expr.result_size(self.irsb.tyenv)
        if tag == "Iex_Const" and isinstance(expr.con.value, int) and bits <= 64:
            value = expr.con.value
            if value >= 1 << 63:
                value -= 1 << 64
            self.facts.add("constant", eid, bits, value)
        elif tag == "Iex_Get":
            loc, width = self.reg(expr.offset, max(1, bits // 8))
            self.facts.add("reg_read", self.stmt, self.func, self.bb, self.order, loc, eid)
            if bits < self.arch.bits:
                self.unknown(eid, f"partial register read {bits} bits")
        elif tag == "Iex_Load":
            self.facts.add("load", self.stmt, self.func, self.address, max(1, bits // 8), self.expr(expr.addr), eid)
        elif tag == "Iex_Binop":
            left, right = (self.expr(arg) for arg in expr.args)
            self.facts.add("binary", eid, expr.op.removeprefix("Iop_"), bits, left, right)
        elif tag == "Iex_Unop":
            self.facts.add("unary", eid, expr.op.removeprefix("Iop_"), bits, self.expr(expr.args[0]))
        elif tag == "Iex_ITE":
            # Path-insensitive union of both alternatives.
            for value in (expr.iftrue, expr.iffalse):
                self.facts.add("copy", self.expr(value), eid)
        else:
            self.unknown(eid, tag)
        return eid

    def parse(self, block, function):
        self.irsb, self.bb, self.func = block.vex, block.addr, function
        self.expression_counter, self.address = 0, block.addr
        last = block.instruction_addrs[-1]
        is_call = self.irsb.jumpkind == "Ijk_Call"
        call_sp_after = None
        for order, stmt in enumerate(self.irsb.statements, 1):
            self.order = order
            if stmt.tag == "Ist_IMark":
                self.address = stmt.addr
                continue
            self.stmt = self.facts.eid(("stmt", self.bb, order))
            self.facts.add("statement", self.stmt, function, self.bb, self.address, order)
            if stmt.tag == "Ist_WrTmp":
                self.facts.add("copy", self.expr(stmt.data), self.tmp(stmt.tmp))
            elif stmt.tag == "Ist_Put":
                bits = stmt.data.result_size(self.irsb.tyenv)
                loc, width = self.reg(stmt.offset, max(1, bits // 8))
                # CALL's hardware push is undone before its FakeRet successor.
                if is_call and self.address == last and loc == self.arch.sp_offset:
                    # VEX can delay an earlier AND/subtraction into this Put.
                    # Keep the actual expression, then undo only the hardware
                    # push; dropping the whole Put would lose software changes.
                    call_sp_after = self.expr(stmt.data)
                    continue
                value = self.expr(stmt.data)
                definition = self.facts.eid(("definition", self.stmt, loc))
                self.facts.add("reg_def", self.stmt, function, self.bb, order, loc, value, definition)
                self.facts.add("copy", value, definition)
                if bits < width * 8:
                    self.unknown(definition, f"partial register write {bits} bits")
            elif stmt.tag == "Ist_Store":
                # The call instruction's return-address push is bookkeeping.
                if is_call and self.address == last:
                    continue
                self.facts.add("store", self.stmt, function, self.address,
                               max(1, stmt.data.result_size(self.irsb.tyenv) // 8),
                               self.expr(stmt.addr), self.expr(stmt.data))
            elif stmt.tag in ("Ist_Exit", "Ist_NoOp", "Ist_AbiHint", "Ist_MBE"):
                continue
            else:
                self.facts.add("unsupported", function, self.address, stmt.tag)
        self.order = len(self.irsb.statements) + 1
        self.stmt = self.facts.eid(("terminator", self.bb))
        self.address = last
        self.facts.add("statement", self.stmt, function, self.bb, last, self.order)
        target = self.expr(self.irsb.next)
        if is_call:
            if call_sp_after is not None:
                snapshot = self.facts.eid(("call_stack", self.stmt))
                word = self.facts.eid(("call_stack_word", self.stmt))
                self.facts.add("constant", word, self.arch.bits, self.arch.bytes)
                self.facts.add("binary", snapshot, f"Add{self.arch.bits}", self.arch.bits, call_sp_after, word)
                self.facts.add("call_stack", self.stmt, snapshot)
                version = self.facts.eid(("call_stack_definition", self.stmt))
                self.facts.add("reg_def", self.stmt, function, self.bb, self.order,
                               self.arch.sp_offset, snapshot, version)
                self.facts.add("copy", snapshot, version)
            machine = block.capstone.insns[-1].insn
            indirect = int(not machine.operands or machine.operands[0].type != 2)
            self.facts.add("call", self.stmt, function, self.bb, last, target, indirect)
            return self.stmt, self.order
        if self.irsb.jumpkind == "Ijk_Ret":
            self.facts.add("return_block", function, self.bb)
        elif self.irsb.jumpkind == "Ijk_Boring":
            if not isinstance(self.irsb.next, pyvex.expr.Const):
                self.facts.add("unsupported", function, last, "indirect jump: CFGFast edges only")
            elif any(start == self.irsb.next.con.value and name != function
                     for name, start, _ in self.facts.rows["function"]):
                self.facts.add("unsupported", function, last, "tail call")
        else:
            self.facts.add("unsupported", function, last, self.irsb.jumpkind)
        return None


Parser = VexParser
