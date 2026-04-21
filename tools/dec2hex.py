import sys

def dec_file_to_hex(input_file, output_file):
    try:
        with open(input_file, "r") as fin, open(output_file, "w") as fout:
            for line in fin:
                line = line.strip()
                if line.isdigit():  # 确保是数字
                    dec_val = int(line)
                    hex_val = hex(dec_val)  # 转为十六进制
                    fout.write(hex_val + "\n")
                else:
                    fout.write(f"Invalid: {line}\n")
        print(f"转换完成，结果已写入 {output_file}")
    except FileNotFoundError:
        print(f"错误: 找不到文件 {input_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("用法: python dec2hex.py 输入文件 输出文件")
    else:
        dec_file_to_hex(sys.argv[1], sys.argv[2])
