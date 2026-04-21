import sys

def filter_facts(input_file, output_file):
    INT32_MIN = -2147483648
    INT32_MAX = 2147483647

    with open(input_file, "r") as fin, open(output_file, "w") as fout:
        for line in fin:
            parts = line.strip().split()
            if len(parts) < 3:
                continue  # 跳过格式错误的行
            try:
                col2 = int(parts[1])
                if INT32_MIN <= col2 <= INT32_MAX:
                    fout.write(line)
            except ValueError:
                continue  # 跳过无法转为整数的行

    print(f"筛选完成，结果已保存到 {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("用法: python3 filterImmFacts.py <输入文件> <输出文件>")
        sys.exit(1)
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    filter_facts(input_file, output_file)
