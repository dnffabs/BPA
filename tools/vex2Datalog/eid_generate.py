"""Small schema-v2 helpers. A temporary always needs an IRSB namespace."""
import pyvex


def getTmpEid(tmp, facts, eid_iter=None, *, block_addr):
    eid = facts.eid(('tmp', block_addr, tmp))
    facts.add('temporary', eid, block_addr, tmp)
    return eid


def getConsEid(con, facts, eid_iter=None):
    eid = facts.eid(('constant', con.size, str(con.value)))
    if isinstance(con.value, int) and con.size <= 64:
        value = con.value - (1 << 64) if con.value >= 1 << 63 else con.value
        facts.add('constant', eid, con.size, value)
    else:
        facts.add('unknown_seed', eid)
    return eid


def getTmpSize(irsb, tmp):
    return pyvex.get_type_size(irsb.tyenv.lookup(tmp))


def getArgSize_Bit(arg, irsb):
    return arg.result_size(irsb.tyenv)
