#
# # 需要分析变量的定义和使用关系，并计算 GEN 和 KILL 集
# # 定义 GEN 集为变量在语句中定义的集合，KILL 集为变量在语句中被重新赋值的集合
#
#
#
# def compute_gen_kill(statements):
#     gen = set()
#     kill = set()
#     for stmt in statements:
#         defined_var = stmt["get_defined_var"]()  # 调用字典中的 lambda 函数
#         used_vars = stmt["get_used_vars"]()      # 调用字典中的 lambda 函数
#
#         if defined_var:
#             kill.update(var for var in gen if var == defined_var)  # 添加到 KILL 集
#             gen.add(defined_var)  # 添加到 GEN 集
#
#     return gen, kill
#
#
# # # 示例输入
# # statements = [
# #     {"stmt": "x = 1", "get_defined_var": lambda: "x", "get_used_vars": lambda: []},
# #     {"stmt": "y = x + 1", "get_defined_var": lambda: "y", "get_used_vars": lambda: ["x"]},
# #     {"stmt": "x = 2", "get_defined_var": lambda: "x", "get_used_vars": lambda: []}
# # ]
# #
# # gen, kill = compute_gen_kill(statements)
# # print("GEN:", gen)
# # print("KILL:", kill)
#
# from collections import defaultdict
#
# def build_du_ud_chains(statements):
#     def_set = dict()# 每个变量的定义点
#     use_set = dict()
#
#     du_chain = dict()
#     ud_chain = dict()
#     # 拿到块的定义点和使用点
#     for stmt in statements:
#         match stmt.tag:
#             case 'Ist_IMark':
#                 continue
#             case 'Ist_Put':
#             #     处理put类型语句
#
#
#             case 'Ist_Store':
#
#             case 'Ist_Exit':
#
#             case 'Ist_WrTmp':
#
#                 # 处理WrTmp语句
#                 match stmt.data.tag:
#                     case "Iex_Const":
#
#                     case "Iex_RdTmp":
#
#                     case "Iex_Get":
#
#                     case "Iex_Load":
#
#                     case "Iex_Binop":
#
#                     case "Iex_Unop":
#
#                     case "Iex_ITE":
#
#
#
# # # 示例输入
# # instructions = [
# #     {"defined_vars": ["a"], "used_vars": []},  # 1: a = 1
# #     {"defined_vars": ["b"], "used_vars": ["a"]},  # 2: b = a + 2
# #     {"defined_vars": ["a"], "used_vars": ["b"]},  # 3: a = b * 3
# #     {"defined_vars": ["c"], "used_vars": ["a", "b"]},  # 4: c = a + b
# # ]
# #
# # du_chain, ud_chain = build_du_ud_chains(instructions)
# # print("DU-Chain:", dict(du_chain))
# # print("UD-Chain:", dict(ud_chain))
