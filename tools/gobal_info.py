import argparse
import os
from elftools.elf.elffile import ELFFile

def extract_sections(binary_path):
    with open(binary_path, 'rb') as f:
        elffile = ELFFile(f)

        target_sections = ['.data', '.bss', '.rodata']
        sections_info = {}

        for section in elffile.iter_sections():
            name = section.name
            if name in target_sections:
                start_addr = section['sh_addr']
                end_addr = start_addr + section['sh_size']
                info = {
                    "name": name,
                    "start_addr": start_addr,   # 保持为十进制
                    "end_addr": end_addr,
                    "size": section['sh_size']
                }
                sections_info[name] = info

        return sections_info


def write_facts(sections_info, outdir):
    # 如果输出目录不存在，自动创建
    os.makedirs(outdir, exist_ok=True)

    for sec_name, info in sections_info.items():
        filename = os.path.join(outdir, sec_name.lstrip('.') + ".facts")
        with open(filename, "w") as f:
            f.write(f"{info['start_addr']}\t{info['end_addr']}\t{info['size']}\n")
        print(f"[+] 已输出 {filename}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="提取 ELF 文件的 .data, .bss, .rodata 段信息 (十进制输出)")
    parser.add_argument("binary", help="输入 ELF 二进制文件路径")
    parser.add_argument("--outdir", default="facts", help="输出目录 (默认: facts)")
    args = parser.parse_args()

    sections = extract_sections(args.binary)
    if not sections:
        print("未找到 .data, .bss, .rodata 段")
    else:
        write_facts(sections, args.outdir)
