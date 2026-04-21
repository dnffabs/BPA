from vex2Datalog import DatalogFacts
from vex2Datalog.operation import TypeDict_Bit


####over
def getArgEid(arg, facts, eid_iter):
    # arg要么Iex_RdTmp，要么Iex_Const，计算其eid
    if arg.tag == 'Iex_RdTmp':
        return getTmpEid(arg.tmp, facts,eid_iter)
    elif arg.tag == 'Iex_Const':
        return getConsEid(arg.con, facts, eid_iter)
    else:
        return -1



####给中间变量分配eid,tmp是中间变量的编号，eid_iter是分配的id的迭代器
def getTmpEid(tmp, facts:DatalogFacts,eid_iter):
    if tmp not in facts.get_loc_vex_exp.keys():
        facts.get_loc_vex_exp[tmp] = next(eid_iter)
    return facts.get_loc_vex_exp[tmp]




##获取参数的大小，arg是参数，irsb_addr是当前指令地址，facts是Facts类
def getArgSize_Bit(arg, irsb):
    if arg.tag == 'Iex_RdTmp':
        return getTmpSize(irsb, arg.tmp)
    elif arg.tag == 'Iex_Const':
        if arg.con.size is None:
            return 0
        else:
            return arg.con.size
    else:
        return -1


def getTmpSize(irsb, tmp):
    tmp_type = irsb.tyenv.types[tmp]
    tmp_size = TypeDict_Bit[tmp_type]
    return tmp_size



##offset是寄存器的偏移，byte_number是寄存器的字节数，facts是Facts类，eid_iter是分配的id的迭代器
def getRegEid(offset, byte_number, facts:DatalogFacts, eid_iter):
    ###size也可以不传
    # print(facts.arch)
    reg_name = facts.arch.translate_register_name(offset, byte_number)
    if reg_name not in facts.get_loc_vex_exp.keys():
        new_eid = next(eid_iter)
        facts.get_loc_vex_exp[reg_name] = new_eid
    return facts.get_loc_vex_exp[reg_name]


    # if (offset, byte_number) not in facts.reg_vex_exp:
    #     new_eid = next(eid_iter)
    #     facts.reg_vex_exp[(offset, byte_number)] = new_eid
    #     facts.regname_vex_exp[facts.arch.translate_register_name(offset, byte_number)] = new_eid
    # return facts.reg_vex_exp[(offset, byte_number)]



#这里的getConsEid函数是用来处理常量的，包括常量表达式、常量值、常量大小
def getConsEid(con, facts:DatalogFacts, eid_iter):
    # 有时候会出现t12 = nan的情况
    # 通常出现在ite语句中iftrue、iffalse位置
    # 将其作为一个size为0，value为0的特殊常量
    # 浮点数常量pass
    # 还有t12 = 0这种情况（0，不是0x00000000，size也是0）
    if con.size is None:
        size = 0
        value = 0
    elif type(con.value) is float:
        return -1
    else:
        size = con.size
        value = con.value
    # 常量表达式
    new_eid = next(eid_iter)
    facts.imm_vex_exp.append((size, value, new_eid))
    return new_eid
    # if (size, value) not in facts.imm_vex_exp:
    #     facts.imm_vex_exp[(size, value)] = next(eid_iter)
    # return facts.imm_vex_exp[(size, value)]

def getUnopEid(bit_number,nvec,data_eid,facts,eid_iter):
    if (bit_number, nvec, data_eid) not in facts.unop_vex_exp:
        facts.unop_vex_exp[(bit_number, nvec, data_eid)] = next(eid_iter)
    return facts.unop_vex_exp[(bit_number, nvec, data_eid)]


def getBinopEid(addr,bit_number,nvec,data_eid1,data_eid2,facts,eid_iter):

    new_eid = next(eid_iter)
    facts.binop_vex_exp.append((addr, nvec, data_eid1, data_eid2, new_eid))
    return new_eid
    # if (bit_number, nvec, data_eid1, data_eid2) not in facts.binop_vex_exp:
    #     facts.binop_vex_exp[(bit_number, nvec, data_eid1, data_eid2)] = next(eid_iter)
    # return facts.binop_vex_exp[(bit_number, nvec, data_eid1, data_eid2)]