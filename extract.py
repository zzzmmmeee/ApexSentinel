# -*- coding: utf-8 -*-
import os
from collections import Counter

def extract_uuids_from_line(line):
    """提取一行中的第2、8、13字段（从0开始索引）"""
    parts = line.strip().split()
    return [parts[1], parts[5]]

def count_unique_uuids_from_file(file_path):
    uuid_counter = Counter()
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            uuids = extract_uuids_from_line(line)
            uuid_counter.update(uuids)
    return len(uuid_counter)


def load_uuids_from_alert_file(file_path):
    """
    从文件中提取 UUID 列表。
    """
    uuids = set()
    with open(file_path, 'r') as f:
        for line in f:
            uuid = line.strip()  # 去除换行符和空格
            if uuid:
                uuids.add(uuid)
    return uuids

def filter_lines_by_uuid(input_file, uuid_set, output_file):
    """
    将 input_file 中第 2 列为 uuid，且出现在 uuid_set 中的行写入 output_file。
    """
    with open(input_file, 'r') as fin, open(output_file, 'w') as fout:
        for line in fin:
            fields = line.strip().split()
            if len(fields) >= 2 and fields[1] in uuid_set or len(fields) >= 6 and fields[5] in uuid_set:
                fout.write(line)

def main():
    # 加载 cadets.txt 的 UUID 集合
    with open("../dataset/theia.txt", "r") as cadets_file:
        cadets_uuids = set(line.strip() for line in cadets_file if line.strip())

    for i in range(18):
        input_filename = f"../dataset/split_theia/split15m_{i}.txt"
        output_filename = f"../dataset/split_labels_theia_process/split15m_labels_{i}.txt"
        common_uuids = set()

        if not os.path.exists(input_filename):
            print(f"文件不存在：{input_filename}，跳过。")
            continue

        with open(input_filename, "r") as infile:
            for line in infile:
                uuids = extract_uuids_from_line(line)
                for uuid in uuids:
                    if uuid in cadets_uuids:
                        common_uuids.add(uuid)

        with open(output_filename, "w") as outfile:
            for uuid in sorted(common_uuids):
                outfile.write(uuid + "\n")

        print(f"{input_filename} 处理完成，共找到 {len(common_uuids)} 个 UUID。")

def count_num_of_process():
    common_uuids = set()
    input_filename = "../dataset/split/split15m_24.txt"
    with open(input_filename, "r") as infile:
        for line in infile:
            uuids = extract_uuids_from_line(line)
            for uuid in uuids:
                common_uuids.add(uuid)
    print(f"共找到 {len(common_uuids)} 个不同的 UUID")
    
def delete_line_range(file_path, start_line, end_line):
    """
    删除文件中从 start_line 到 end_line 的所有行（包含这两行），行号从0开始。
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # 保留不在删除范围内的行
    new_lines = [line for idx, line in enumerate(lines) if idx < start_line or idx > end_line]

    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)

    print(f"已成功删除第 {start_line} 到第 {end_line} 行（共 {end_line - start_line + 1} 行）")

if __name__ == "__main__":
    # main()
    #Step 1: 读取 2.txt 中所有 UUID
    uuid_set = load_uuids_from_alert_file("../result/alert_0.txt")

    # Step 2: 过滤 1.txt 中的行，写入 3.txt
    filter_lines_by_uuid("../dataset/split_theia/split15m_0.txt", uuid_set, "../test/0.txt")
    # count_num_of_process()
    # file_path = '../test/2.txt'  # 替换成你的文件路径
    # unique_uuid_count = count_unique_uuids_from_file(file_path)
    # print(f"不同 UUID 的数量为: {unique_uuid_count}")
    # file_path = '../test/15.txt'  
    # unique_uuid_count = count_unique_uuids_from_file(file_path)
    # print(f"不同 UUID 的数量为: {unique_uuid_count}")
    # delete_line_range("../result_new3/fp_detail.txt", 0, 30551)
    # with open("../dataset/split_theia/split15m_10.txt", "r") as infile:
    #     for line in infile:
    #         uuids = extract_uuids_from_line(line)