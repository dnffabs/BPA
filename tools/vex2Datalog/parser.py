from vex2Datalog.DatalogFacts import DatalogFacts
from vex2Datalog.Jump_kinds import collect_jumpkinds
from vex2Datalog.eid_generate import getTmpEid, getConsEid, getArgEid, getArgSize_Bit, getTmpSize, getRegEid, \
    getUnopEid, getBinopEid
from vex2Datalog.operation import UnopDict, BiNopDict


# parse the block_vex 2 datalog program
# stmts是block中对应的VEX语句,处理单个block
# 解析器的主要功能是将VEX语句转换为Datalog规则，并将规则加入facts中
# 解析器的输入是VEX语句，输出是Datalog规则
class Parser:
    # 用于存储Datalog规则
    facts = DatalogFacts()
    # 用于生成唯一的id
    iterator = iter(range(1, 100_000_000_000))
    #IRSB
    irsb = None
    #IRSB地址
    irsbAddr = 0
    # 指令对应的地址
    instructionAddr = 0
    # 指令中IR对应的先后顺序
    irOrder = 0
    #指令集
    stmts = None


    # # 初始化解析器
    # def __init__(self, irsb):
    #     Parser.irsbAddr = irsb.addr
    #     self.stmts = irsb.statements

    @staticmethod
    def initialize_parser(irsb,arch):
        Parser.facts.arch = arch
        Parser.irsb = irsb
        Parser.irsbAddr = irsb.addr
        Parser.stmts = irsb.statements


    #获取facts
    @classmethod
    def get_facts(cls):
        return cls.facts

    #获取iterator
    @classmethod
    def get_iterator(cls):
        return cls.iterator


    @classmethod
    def parse_block_vex(cls):


        # 处理指令集
        for stmt in cls.stmts:
            # a = a + 1
            # if a == 15:
            #     break
            match stmt.tag:
                case 'Ist_IMark':
                    #指令顺序
                    cls.irOrder = 0
                    #对应的指令地址
                    cls.instructionAddr = stmt.addr
                    # 添加imark表达式
                    if cls.irsbAddr not in cls.facts.irsbImark.keys():
                        cls.facts.irsbImark[cls.irsbAddr] = []
                    cls.facts.irsbImark[cls.irsbAddr].append((cls.instructionAddr, cls.irOrder, stmt.tag))

                case 'Ist_Put':
                    # 处理Put语句
                    cls.irOrder += 1
                    #获取data的eid
                    data_eid = getArgEid(stmt.data,cls.facts,cls.iterator)
                    ##获取数据大小
                    data_size_bit = getArgSize_Bit(stmt.data, cls.irsb)
                    ##获取寄存器eid
                    reg_eid = getRegEid(stmt.offset, data_size_bit // 8, cls.facts, cls.iterator)
                    ##添加Put语句(设置loc)
                    cls.facts.set_loc_vex.append((cls.irsbAddr, cls.instructionAddr, cls.irOrder, data_size_bit//8, data_eid, reg_eid))

                case 'Ist_Store':
                    # print(stmt)
                    cls.irOrder += 1
                    # 处理Store语句
                    # # 获取addr的eid
                    # print(type(stmt.addr))

                    if str(type(stmt.addr)) == "<class 'pyvex.expr.RdTmp'>":
                        addr_eid = getTmpEid(stmt.addr.tmp, cls.facts, cls.iterator)
                    elif str(type(stmt.addr)) == "<class 'pyvex.expr.Const'>":
                        addr_eid = getConsEid(stmt.addr.con, cls.facts, cls.iterator)
                    ##获取data的eid
                    data_eid = getArgEid(stmt.data, cls.facts, cls.iterator)
                    ##获取data的大小
                    data_size_bit = getArgSize_Bit(stmt.data, cls.irsb)
                    #添加Store语句
                    cls.facts.set_mem_vex.append((cls.irsbAddr, cls.instructionAddr, cls.irOrder, data_size_bit//8, data_eid,addr_eid))

                case 'Ist_Exit':
                    cls.irOrder += 1
                    #获取guard的eid
                    guard_eid = getArgEid(stmt.guard, cls.facts, cls.iterator)
                    #获取dst的eid
                    dst_eid = getConsEid(stmt.dst, cls.facts, cls.iterator)
                    #获取jumpkind的eid
                    jumpkind = stmt.jumpkind
                    offsIP = stmt.offsIP
                    dst_size_bit = stmt.dst.size
                    cls.facts.exit_vex_exp.append((cls.irsbAddr, cls.instructionAddr, cls.irOrder,0,guard_eid, dst_eid, jumpkind, offsIP, dst_size_bit))


                case 'Ist_WrTmp':
                    cls.irOrder += 1
                    # 处理WrTmp语句
                    match stmt.data.tag:
                        case "Iex_Const":
                        # 输出该stmt
                            print(stmt)
                            print("you need to address this stmt")
                        case "Iex_RdTmp":
                            # t6 = t15
                            tmp1_eid = getTmpEid(stmt.tmp, cls.facts, cls.iterator)
                            data_size_bit = getArgSize_Bit(stmt.data, cls.irsb)
                            tmp2_eid = getTmpEid(stmt.data.tmp, cls.facts, cls.iterator)
                            cls.facts.set_loc_vex.append((cls.irsbAddr, cls.instructionAddr, cls.irOrder, data_size_bit//8, tmp2_eid, tmp1_eid))
                        case "Iex_Get":
                            # t6 = GET:I32(t15)
                            tmp_eid = getTmpEid(stmt.tmp, cls.facts, cls.iterator)
                            data_size_bit = getTmpSize(cls.irsb,stmt.tmp)
                            reg_eid = getRegEid(stmt.data.offset, data_size_bit // 8, cls.facts, cls.iterator)
                            cls.facts.set_loc_vex.append((cls.irsbAddr, cls.instructionAddr, cls.irOrder, data_size_bit//8, reg_eid, tmp_eid))
                            #可能会出现t2 = GET:I32(esp)的情况，需要处理


                        case "Iex_Load":
                            # t6 = t15 + t16
                            addr = stmt.data.addr
                            # print(stmt)
                            # # 把addr转化为十进制
                            # addr = int(str(addr), 16)
                            data_size_bit = getTmpSize(cls.irsb,stmt.tmp)
                            tmp_eid = getTmpEid(stmt.tmp, cls.facts, cls.iterator)
                            cls.facts.get_mem_vex_exp.append((cls.irsbAddr, cls.instructionAddr, cls.irOrder, data_size_bit//8, addr, tmp_eid))
                        case "Iex_Binop":
                            # t6 = t15 + t16
                            print("this is a Binop stmt")
                            print(stmt)
                            print(stmt.data.args[0])
                            print(stmt.data.args[1])
                            arg0_eid = getArgEid(stmt.data.args[0],  cls.facts, cls.iterator)
                            arg1_eid = getArgEid(stmt.data.args[1],  cls.facts, cls.iterator)
                            if stmt.data.op not in BiNopDict.keys():
                                bit_number = -1
                                bvec = -1
                            else:
                                bit_number, bvec = BiNopDict[stmt.data.op]
                            print(bit_number,bvec)
                            binopeid = getBinopEid(cls.instructionAddr,bit_number,bvec,arg0_eid,arg1_eid,cls.facts,cls.iterator)
                            tmp2_eid = getTmpEid(stmt.tmp, cls.facts, cls.iterator)
                            cls.facts.set_loc_vex.append((cls.irsbAddr, cls.instructionAddr, cls.irOrder, bit_number, binopeid, tmp2_eid))
                        case "Iex_Unop":
                            print("this is a Unop stmt")
                            # t6 = not(t15)
                            # t16 = 64to8(0x0000000000000001)
                            # print(stmt)
                            # print(stmt.data.args[0])
                            # print(str(type(stmt.data.args[0])))
                            # 如果stmt.data.args[0]中有tmp，则需要处理
                            if str(type(stmt.data.args[0])) == "<class 'pyvex.expr.RdTmp>":
                                tmp1 = stmt.data.args[0].tmp
                                tmp1_eid = getTmpEid(tmp1, cls.facts, cls.iterator)
                                if stmt.data.op not in UnopDict.keys():
                                    bit_number = -1
                                    bvec = -1
                                else:
                                    bit_number, bvec = UnopDict[stmt.data.op]
                                unopeid = getUnopEid(bit_number, bvec, tmp1_eid, cls.facts, cls.iterator)
                                tmp2_eid = getTmpEid(stmt.tmp, cls.facts, cls.iterator)
                                cls.facts.set_loc_vex.append((cls.irsbAddr, cls.instructionAddr, cls.irOrder, bit_number, unopeid, tmp2_eid))
                            elif str(type(stmt.data.args[0])) == "<class 'pyvex.expr.Const'>":
                                # 处理常量
                                tmp1 = stmt.data.args[0].con
                                tmp1_eid = getConsEid(tmp1, cls.facts, cls.iterator)
                                if stmt.data.op not in UnopDict.keys():
                                    bit_number = -1
                                    bvec = -1
                                else:
                                    bit_number, bvec = UnopDict[stmt.data.op]
                                unopeid = getUnopEid(bit_number, bvec, tmp1_eid, cls.facts, cls.iterator)
                                tmp2_eid = getTmpEid(stmt.tmp, cls.facts, cls.iterator)
                                cls.facts.set_loc_vex.append((cls.irsbAddr, cls.instructionAddr, cls.irOrder, bit_number, unopeid, tmp2_eid))

                        case "Iex_ITE":
                            # t6 = ITE(t15,t16,t17)
                            print("this is a ITE stmt=======================>")
                            print(stmt)

        # 最后处理对应的jump指令
        collect_jumpkinds(cls.irsb, cls.facts)
















