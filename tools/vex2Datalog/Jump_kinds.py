"""
一共有三种跳转方式

1. Ijk_Boring: 无条件跳转，即常规的跳转指令，如 jmp

2. Ijk_Call: 调用函数，即 call 指令

3. Ijk_Ret: 返回函数，即 ret 指令
可以通过 block.vex.jumpkind 来获取当前 block 的跳转类型。

"""
def collect_jumpkinds(irsb,facts):
    # 处理irsb的跳转指令
    jumpkind = irsb.jumpkind

    match jumpkind:
        case "Ijk_Boring":
        #条件跳转
            facts.jmp_vex_exp.append(("Ijk_Boring",hex(irsb.addr),hex(facts.irsbImark[irsb.addr][-1][0]),irsb.constant_jump_targets))
        case "Ijk_Call":
        #函数调用，函数指针
            facts.call_vex_exp.append(("Ijk_Call",hex(irsb.addr),hex(facts.irsbImark[irsb.addr][-1][0]),irsb.constant_jump_targets))
        case "Ijk_Ret":
        #函数返回
            facts.ret_vex_exp.append(("Ijk_Ret",hex(irsb.addr),hex(facts.irsbImark[irsb.addr][-1][0]),irsb.constant_jump_targets))


