import re

# 方法1：使用集合
def count_common_lines(file1, file2):
    with open(file1, 'r') as f1:
        set1 = set(line.strip() for line in f1 if line.strip())
    
    with open(file2, 'r') as f2:
        set2 = set(line.strip() for line in f2 if line.strip())
    
    common_lines = set1 & set2
    return len(common_lines)

# 示例调用
file1 = '../result_test/fp_detail.txt'
file2 = '../result1/fp_detail.txt'
common_count = count_common_lines(file1, file2)
print(f"Number of common lines: {common_count}")