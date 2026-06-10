def count_matching_uuids(alert_file, label_file):
    # 读取 alert.txt 中的 UUID（每行格式为 "Node: UUID, Suspicion Score: ..."）
    with open(alert_file, 'r') as f:
        alert_uuids = set(line.split(',')[0].split(':')[1].strip() for line in f if line.startswith("Node:"))

    # 读取 label 文件中的 UUID（每行一个 UUID）
    with open(label_file, 'r') as f:
        label_uuids = set(line.strip() for line in f if line.strip())

    # 求交集
    matched = alert_uuids & label_uuids

    print(f"共有 {len(matched)} 个 UUID 出现在两个文件中。")
    print("匹配的 UUID：")
    for uuid in matched:
        print(uuid)

# 调用示例
# count_matching_uuids("../result/alert_sum.txt", "../dataset/subject_M.txt")
for i in range(0, 113):
    count_matching_uuids(f"../dataset/split_labels3/split15m_labels_{i}.txt", f"../dataset/split_labels/split15m_labels_{i}.txt")