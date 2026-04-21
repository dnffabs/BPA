# pyvex.expr.Binop
# binop 表
# key=tag, value=(bit_number, bvec)
# bpa用于生成mba ir时应该只关注地址运算，这里将浮点数与SIMD指令的运算符都忽略掉
# 但是vex ir里没找到ROL、ROR对应的运算符，暂且记下
BiNopDict = {
    # 全部改为单词形式，与vex ir保持一致
    'Iop_Add8': (8, "Add8"), 'Iop_Add16': (16, "Add16"), 'Iop_Add32': (32, "Add32"), 'Iop_Add64': (64, "Add64"),
    'Iop_Sub8': (8, "Sub8"), 'Iop_Sub16': (16, "Sub16"), 'Iop_Sub32': (32, "Sub32"), 'Iop_Sub64': (64, "Sub64"),
    'Iop_Mul8': (8, "Mul8"), 'Iop_Mul16': (16, "Mul16"), 'Iop_Mul32': (32, "Mul32"), 'Iop_Mul64': (64, "Mul64"),
    # MullU、MullS在后边
    'Iop_And8': (8, "And8"), 'Iop_And16': (16, "And16"), 'Iop_And32': (32, "And32"), 'Iop_And64': (64, "And64"),
    'Iop_Or8': (8, "Or8"), 'Iop_Or16': (16, "Or16"), 'Iop_Or32': (32, "Or32"), 'Iop_Or64': (64, "Or64"),
    'Iop_Xor8': (8, "Xor8"), 'Iop_Xor16': (16, "Xor16"), 'Iop_Xor32': (32, "Xor32"), 'Iop_Xor64': (64, "Xor64"),
    # 数据以补码形式存放，所以算术左移与逻辑左移等价？目前想不明白，先这样。
    'Iop_Shl8': (8, "Shl8"), 'Iop_Shl16': (16, "Shl16"), 'Iop_Shl32': (32, "Shl32"), 'Iop_Shl64': (64, "Shl64"),
    'Iop_Shr8': (8, "Shr8"), 'Iop_Shr16': (16, "Shr16"), 'Iop_Shr32': (32, "Shr32"), 'Iop_Shr64': (64, "Shr64"),
    'Iop_Sar8': (8, "Sar8"), 'Iop_Sar16': (16, "Sar16"), 'Iop_Sar32': (32, "Sar32"), 'Iop_Sar64': (64, "Sar64"),
    'Iop_DivU32': (32, "DivU32"),
    'Iop_DivS32': (32, "DivS32"),
    'Iop_DivU64': (64, "DivU64"),
    'Iop_DivS64': (64, "DivS64"),
    'Iop_DivU32E': (32, "DivU32E"),
    'Iop_DivS32E': (32, "DivS32E"),
    'Iop_DivU64E': (64, "DivU64E"),
    'Iop_DivS64E': (64, "DivS64E"),
    'Iop_DivModU64to32': (64, "DivModU64to32"), 'Iop_DivModU128to64': (128, "DivModU128to64"),
    'Iop_DivModS64to32': (64, "DivModS64to32"), 'Iop_DivModS128to64': (128, "DivModS128to64"),
    'Iop_DivModS64to64': (128, "DivModS64to32"),

    'Iop_MullS8': (16, "MullS8"), 'Iop_MullS16': (32, "MullS16"), 'Iop_MullS32': (64, "MullS32"),
    'Iop_MullS64': (128, "MullS64"),
    'Iop_MullU8': (16, "MullU8"), 'Iop_MullU16': (32, "MullU16"), 'Iop_MullU32': (64, "MullU32"),
    'Iop_MullU64': (128, "MullU64"),

    # 一些二元的convert运算
    'Iop_8HLto16': (16, '8HLto16'), 'Iop32HLto64': (64, '32HLto64'), 'Iop64HLto128': (128, '64HLto128'),

    # compare运算
    'Iop_CmpEQ8': (1, 'CmpEQ8'), 'Iop_CmpEQ16': (1, 'CmpEQ16'), 'Iop_CmpEQ32': (1, 'CmpEQ32'),
    'Iop_CmpEQ64': (1, 'CmpEQ64'),
    'Iop_CmpNE8': (1, 'CmpNE8'), 'Iop_CmpNE16': (1, 'CmpNE16'), 'Iop_CmpNE32': (1, 'CmpNE32'),
    'Iop_CmpNE64': (1, 'CmpNE64'),

    # cas运算先pass掉

    # expensive的compare运算
    'Iop_ExpCmpNE8': (1, 'ExpCmpNE8'), 'Iop_ExpCmpNE16': (1, 'ExpCmpNE16'), 'Iop_ExpCmpNE32': (1, 'ExpCmpNE32'),
    'Iop_ExpCmpNE64': (1, 'ExpCmpNE64'),

    # standard integer comparisons
    'Iop_CmpLT32S': (1, 'CmpLT32S'), 'Iop_CmpLT64S': (1, 'CmpLT64S'),
    'Iop_CmpLE32S': (1, 'CmpLE32S'), 'Iop_CmpLE64S': (1, 'CmpLE64S'),
    'Iop_CmpLT32U': (1, 'CmpLT32U'), 'Iop_CmpLT64U': (1, 'CmpLT64U'),
    'Iop_CmpLE32U': (1, 'CmpLE32U'), 'Iop_CmpLE64U': (1, 'CmpLE64U'),
}

# 一元运算表
UnopDict = {
    # 主要是vex ir中的convert运算，这里只处理整数运算
    # 还有一些convert运算是二元运算符，比如16HLto32，写入BiNopDict中。
    # widening
    'Iop_8Uto16': (16, "8Uto16"), 'Iop_8Uto32': (32, "8Uto32"), 'Iop_8Uto64': (64, "8Uto64"),
    'Iop_16Uto32': (32, "16Uto32"), 'Iop_16Uto64': (64, "16Uto64"),
    'Iop_32Uto64': (64, "32Uto64"),
    'Iop_8Sto16': (16, "8Sto16"), 'Iop_8Sto32': (32, "8Sto32"), 'Iop_8Sto64': (64, "8Sto64"),
    'Iop_16Sto32': (32, "16Sto32"), 'Iop_16Sto64': (64, "16Sto64"),
    'Iop_32Sto64': (64, "32Sto64"),
    # narrowing
    'Iop_64to8': (8, '64to8'), "Iop_32to8": (8, "32to8"), 'Iop_64to16': (16, "64to16"),
    'Iop_16to8': (8, '16to8'), 'Iop_16HIto8': (8, '16HIto8'),
    'Iop32to16': (16, '32to16'), 'Iop32HIto16': (16, '32HIto16'),
    'Iop64to32': (32, '64to32'), 'Iop64HIto32': (32, '64HIto32'),
    'Iop128to64': (64, '128to64'), 'Iop128HIto64': (64, '128HIto64'),
    # 1-bit stuff
    'Iop_Not1': (1, 'Not1'),
    'Iop_32to1': (1, '32to1'),
    'Iop_64to1': (1, '64to1'),
    'Iop_1Uto8': (8, '1Uto8'),
    'Iop_1Uto16': (16, '1Uto16'),  # 不知道为什么，vex ir里有1Sto16，没有1Uto16，这里先加上，大不了不用。
    'Iop_1Uto32': (32, '1Uto32'),
    'Iop_1Uto64': (64, '1Uto64'),
    'Iop_1Sto8': (8, '1Sto8'),
    'Iop_1Sto16': (16, '1Sto16'),
    'Iop_1Sto32': (32, '1Sto32'),
    'Iop_1Sto64': (64, '1Sto64'),

    # not运算
    'Iop_Not8': (8, 'Not8'), 'Iop_Not16': (16, 'Not16'), 'Iop_Not32': (32, 'Not32'), 'Iop_Not64': (64, 'Not64'),

    # wierdo integer stuff
    'Iop_Clz32': (32, 'Clz32'), 'Iop_Clz64': (64, 'Clz64'),
    'Iop_Ctz32': (32, 'Ctz32'), 'Iop_Ctz64': (64, 'Ctz64'),
}

# size_byte 表
TypeDict_Byte = {
    'Ity_I8': 1, 'Ity_I16': 2, 'Ity_I32': 4, 'Ity_I64': 8, 'Ity_I128': 16
    # 其他的不予考虑
}

# size_bit 表
TypeDict_Bit = {
    'Ity_I1': 1, 'Ity_I8': 8, 'Ity_I16': 16, 'Ity_I32': 32, 'Ity_I64': 64, 'Ity_I128': 128, 'Ity_F32': 32, 'Ity_F64': 64, 'Ity_V128' : 128
}
