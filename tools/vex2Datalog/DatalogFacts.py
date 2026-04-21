import os


class DatalogFacts:
    def __init__(self):
        ##put_reg相关信息|写寄存器
        self.arch = None

        self.set_loc_vex = []

        ##set_mem相关信息|写内存
        self.set_mem_vex = []

        ##一元运算相关信息|操作
        self.unop_vex_exp = {}

        ##二元y运算相关信息|操作
        self.binop_vex_exp = []

        ##get_reg相关信息|读寄存器
        self.get_loc_vex_exp = {}

        ##exit相关信息|退出
        self.exit_vex_exp = []

        ##get_mem相关信息|读内存
        self.get_mem_vex_exp = []

        ##const相关信息|常量
        self.imm_vex_exp = []

        ##语句序号相关信息|语句序号
        self.irsbImark = {}

        ##jump相关信息
        self.jmp_vex_exp = []

        ##call相关信息
        self.call_vex_exp = []

        ##return相关信息
        self.ret_vex_exp = []


    def PrintFacts(self):
        print("====================> Datalog Facts <=================")
        print("the binary of Facts is:")
        print("irsbImark:", self.irsbImark)
        print("get_loc_vex_exp:", self.get_loc_vex_exp)
        print("get_mem_vex_exp:", self.get_mem_vex_exp)
        print("set_loc_vex:", self.set_loc_vex)
        print("set_mem_vex:", self.set_mem_vex)
        print("unop_vex_exp:", self.unop_vex_exp)
        print("binop_vex_exp:", self.binop_vex_exp)
        print("imm_vex_exp:", self.imm_vex_exp)
        print("exit_vex_exp:", self.exit_vex_exp)
        print("jmp_vex_exp:", self.jmp_vex_exp)
        print("call_vex_exp:", self.call_vex_exp)
        print("ret_vex_exp:", self.ret_vex_exp)
        print("====================> End of Datalog Facts <=")

    def write_to_file(self, filedir):

        new = []
        with open(os.path.join(filedir, "set_loc_vex.facts"), "w") as set_loc_vex:
            for item in self.set_loc_vex:
                irsbAddr = item[0]
                tmp = str(irsbAddr) + '\t' + str(item[1]) + '\t' + str(item[2]) + '\t' + str(
                    item[3]) + '\t'+ str(item[4]) + '\t' + str(item[5])
                new.append(tmp)
            set_loc_vex.write('\n'.join(new))

        new = []
        with open(os.path.join(filedir, "set_mem_vex.facts"), "w") as set_mem_vex:
            for item in self.set_mem_vex:
                irsbAddr = item[0]
                tmp = str(irsbAddr) + '\t' + str(item[1]) + '\t' + str(item[2]) + '\t' + str(
                    item[3]) + '\t'+ str(item[4]) + '\t' + str(item[5])
                new.append(tmp)
            set_mem_vex.write('\n'.join(new))

        new = []
        with open(os.path.join(filedir, "get_loc_vex_exp.facts"), "w") as get_loc_vex_exp:
            for key in self.get_loc_vex_exp:
                tmp = str(key) + '\t' +  str(self.get_loc_vex_exp[key])
                new.append(tmp)
            get_loc_vex_exp.write('\n'.join(new))

        new = []
        with open(os.path.join(filedir, "get_mem_vex_exp.facts"), "w") as get_mem_vex_exp:
            for item in self.get_mem_vex_exp:
                irsbAddr = item[0]
                tmp = str(irsbAddr) + '\t' + str(item[1]) + '\t' + str(item[2]) + '\t' + str(
                    item[3]) + '\t'+ str(item[4]) + '\t' + str(item[5])
                new.append(tmp)
            get_mem_vex_exp.write('\n'.join(new))

        new = []
        with open(os.path.join(filedir, "unop_vex_exp.facts"), "w") as unop_vex_exp:
            for key in self.unop_vex_exp:
                tmp = str(key) + '\t' + str(self.unop_vex_exp[key])
                new.append(tmp)
            unop_vex_exp.write('\n'.join(new))

        new = []
        with open(os.path.join(filedir, "binop_vex_exp.facts"), "w") as binop_vex_exp:
            for item in self.binop_vex_exp:
                tmp = str(item[0]) + '\t' + str(item[1]) + '\t' + str(item[2]) + '\t' + str(item[3]) + '\t'+ str(item[4])
                new.append(tmp)
            binop_vex_exp.write('\n'.join(new))

        new = []
        with open(os.path.join(filedir, "imm_vex_exp.facts"), "w") as imm_vex_exp:
            for item in self.imm_vex_exp:
                tmp = str(item[0]) + '\t' + str(item[1]) + '\t' + str(item[2])
                new.append(tmp)
            imm_vex_exp.write('\n'.join(new))

        new = []
        with open(os.path.join(filedir, "exit_vex_exp.facts"), "w") as exit_vex_exp:
            for item in self.exit_vex_exp:
                tmp = str(item[0]) + '\t' + str(item[1]) + '\t' + str(item[2]) + '\t' + str(
                    item[3]) + '\t'+ str(item[4]) + '\t' + str(item[5]) + '\t' + str(item[6]) + '\t' + str(item[7]) + '\t' + str(item[8])
                new.append(tmp)
            exit_vex_exp.write('\n'.join(new))

        new = []
        with open(os.path.join(filedir, "irsbImark.facts"), "w") as irsbImark:
            for key in self.irsbImark:
                tmp = str(key) + '\t' + str(self.irsbImark[key])
                new.append(tmp)
            irsbImark.write('\n'.join(new))


        new = []
        with open(os.path.join(filedir, "jmp_vex_exp.facts"), "w") as jmp_vex_exp:
            for item in self.jmp_vex_exp:
                tmp = str(item[0]) + '\t' + str(item[1]) + '\t' + str(item[2]) + '\t' + str(item[3])
                new.append(tmp)
            jmp_vex_exp.write('\n'.join(new))

        new = []
        with open(os.path.join(filedir, "call_vex_exp.facts"), "w") as call_vex_exp:
            for item in self.call_vex_exp:
                tmp = str(item[0]) + '\t' + str(item[1]) + '\t' + str(item[2]) + '\t' + str(item[3])
                new.append(tmp)
            call_vex_exp.write('\n'.join(new))

        new = []
        with open(os.path.join(filedir, "ret_vex_exp.facts"), "w") as ret_vex_exp:
            for item in self.ret_vex_exp:
                tmp = str(item[0]) + '\t' + str(item[1]) + '\t' + str(item[2]) + '\t' + str(item[3])
                new.append(tmp)
            ret_vex_exp.write('\n'.join(new))
