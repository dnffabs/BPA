import angr
import os


# 读取二进制文件，提取出CFG,显式调用angr的CFGFast分析器
def extract_cfg(binary_path):
    """
    使用angr提取二进制文件的CFG。
    :param binary_path: 二进制文件路径
    :return: angr的CFG实例
    :raises: FileNotFoundError, ValueError
    """
    if not os.path.isfile(binary_path):
        raise FileNotFoundError(f"Binary file not found: {binary_path}")
    try:
        project = angr.Project(binary_path, auto_load_libs=False)
        # 分析CFG
        print("Extracting CFG...")
        # 使用静态分析的方式来构建CFG，速度更快
        cfg = project.analyses.CFGFast()
        # 输出cfg图

        return cfg, project.arch
    except Exception as e:
        raise ValueError(f"Failed to extract CFG: {e}")


# 打印CFG
def print_cfg(cfg):
    """
    打印CFG的基本信息。

    :param cfg: angr的CFG实例
    """
    print("CFG Details:")
    try:
        print("CFG Graph Nodes:", len(cfg.graph.nodes))
        print("CFG Graph Edges:", len(cfg.graph.edges))
    except AttributeError:
        raise ValueError("Invalid CFG object provided.")


# 保存CFG为DOT文件
def save_cfg_as_dot(cfg, output_path, format='png'):
    """
    保存CFG为指定格式的文件。

    :param cfg: angr的CFG实例
    :param output_path: 保存文件路径（不含扩展名）。
    :param format: 文件格式，例如 'png', 'pdf', 'svg' 等。
    :raises: ValueError, FileNotFoundError
    """
    if not hasattr(cfg, "graph"):
        raise ValueError("CFG object does not contain a graph.")

    valid_formats = ['png', 'pdf', 'svg']
    if format not in valid_formats:
        raise ValueError(f"Invalid format '{format}'. Supported formats: {', '.join(valid_formats)}")

    dot_file_path = f"{output_path}.dot"
    output_file_path = f"{output_path}.{format}"

    try:
        # 保存为DOT文件
        cfg.graph.draw(dot_file_path, as_dot=True)
        print(f"DOT file saved at: {dot_file_path}")

        # 使用Graphviz保存为指定格式文件
        cfg.graph.draw(output_file_path, format=format)
        print(f"{format.upper()} file saved at: {output_file_path}")
    except Exception as e:
        raise ValueError(f"Failed to save CFG as {format.upper()}: {e}")


#通过cfg拿到对应的nodes
def extract_nodes(cfg):
    """
    提取CFG的节点信息。
    :param cfg: angr的CFG实例
    :return: 节点列表
    :raises: ValueError
    """
    # 读取CFG是否为空
    return cfg._nodes.values()


def extract_block(node):
    """
    提取节点对应的基本块。
    :param node:
    :return:
    """
    block = node.block
    if block is not None and block.size != 0:
        return block
    else:
        print("The block is empty or None")
        return None

