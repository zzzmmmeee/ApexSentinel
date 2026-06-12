import csv
import os
import glob
from collections import defaultdict
import hashlib
import re
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Process CSV log files and perform MAE detection")
    
    # 必需参数
    parser.add_argument(
        "--input_csv", "-i",
        required=True,
        help="Input CSV file path"
    )
    parser.add_argument(
        "--output_csv_dir", "-c",
        required=True,
        help="Directory to store categorized CSV files"
    )
    parser.add_argument(
        "--output_org_txt_dir", "-o",
        required=True,
        help="Directory for raw data TXT output (filtered by MAE detection results)"
    )
    parser.add_argument(
        "--output_mae_txt_dir", "-m",
        required=True,
        help="Directory for MAE detection TXT output"
    )
    parser.add_argument(
        "--output_split_dir", "-s",
        required=True,
        help="Directory for storing split data"
    )
    
    return parser.parse_args()


def replace_uuid(match):
    uuid_str = match.group(0)
    hash_obj = hashlib.sha256(uuid_str.encode('utf-8'))
    hash_digest = hash_obj.hexdigest()
    hash_value = int(hash_digest[:2], 16)
    mod_value = hash_value % 100
    return str(mod_value)

def process_line(line):
    processed_line = re.sub(
        r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        replace_uuid,
        line
    )
    pattern_ip = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    line_p = re.sub(pattern_ip, "IP_address", processed_line)
    return line_p

def process_log(csv_file,org_file,mae_file):
    fields_to_keep = [
        'timestampnanos',
        'subject_com.bbn.tc.schema.avro.cdm18.uuid',
        'properties_map_ppid',
        'properties_map_exec',
        'type',
        'object_type',
        'predicateobject_com.bbn.tc.schema.avro.cdm18.uuid',
        'predicateobjectpath_string',
        'object2_type',
        'predicateobject2_com.bbn.tc.schema.avro.cdm18.uuid',
        'predicateobject2path_string',
        'properties_map_cmdline',
        'properties_map_return_value',
        'lable'
    ]
    
    fields_all = [
      "timestampnanos",
      "subject_com.bbn.tc.schema.avro.cdm18.uuid",
      "properties_map_ppid",
      "properties_map_exec",
      "type",
      "name_string",
      "object_type",
      "predicateobject_com.bbn.tc.schema.avro.cdm18.uuid",
      "predicateobjectpath_string",
      "properties_map_address",
      "properties_map_port",
      "object2_type",
      "predicateobject2_com.bbn.tc.schema.avro.cdm18.uuid",
      "predicateobject2path_string",
      "properties_map_cmdline",
      "properties_map_return_value",
      "properties_map_fd",
      "properties_map_ret_fd1",
      "properties_map_ret_fd2",
      "parameters_array_name_string",
      "size_long",
      "parameters_array_valuedatatype",
      "parameters_array_type",
      "lable"
    ]

    with open(csv_file, 'r', newline='') as csvfile, open(org_file, 'w') as orgfile, open(mae_file, 'a') as maefile:
        reader = csv.DictReader(csvfile)
        writer1 = csv.writer(orgfile, delimiter=' ')
        writer2 = csv.writer(maefile, delimiter=' ')
        
        count = 0
        timefirst=0
        num = 0
        for row in reader:
            row['type'] = row['type'].replace("EVENT_", "")
            writer1.writerow([row[field] for field in fields_all])

            if count==0:
                timefirst = int(row['timestampnanos'])
                row['timestampnanos'] = 0
            else:
                row['timestampnanos'] = int(row['timestampnanos']) - timefirst
            writer2.writerow([row[field] for field in fields_to_keep])

            count+=1
            num+=1
            if count%20 == 0:
                count = 0    

    print("Conversion complete.")

def split_csv_by_subject(input_csv_path, output_directory):
    data_by_subject = defaultdict(list)

    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    with open(input_csv_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            subject = row['subject_com.bbn.tc.schema.avro.cdm18.uuid']
            data_by_subject[subject].append(row)

    for subject, rows in data_by_subject.items():
        output_csv_path = os.path.join(output_directory, f"{subject}.csv")
        with open(output_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=reader.fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)

    print(f"Data has been split into multiple CSV files based on the 'subject' column.")

def split_file_org(input_file, output_file_directory, lines_per_file=24):
    file_name = os.path.basename(input_file)
    txt_file_name = os.path.splitext(file_name)[0]
    with open(input_file, 'r') as f:
        lines = f.readlines()

    num_files = len(lines) // lines_per_file

    for i in range(num_files):
        start = i * lines_per_file
        end = start + lines_per_file
        label = 0
        for line in lines[start:end]:
            line_rs = line.rstrip()
            if line_rs.endswith("M"):
                label = 1
                print(txt_file_name)
                break

        output_file = f'{label}_{txt_file_name}_{i+1}.txt'
        output_file_path = os.path.join(output_file_directory, output_file)
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        with open(output_file_path, 'w') as f:
            f.writelines(lines[start:end])

def split_file_mae(input_file, output_file_directory, lines_per_file=24):
    file_name = os.path.basename(input_file)
    txt_file_name = os.path.splitext(file_name)[0]
    with open(input_file, 'r') as f:
        lines = f.readlines()
    
    num_files = len(lines) // lines_per_file

    for i in range(num_files):
        start = i * lines_per_file
        end = start + lines_per_file
        label = 0
        for line in lines[start:end]:
            line_rs = line.rstrip()
            if line_rs.endswith("M"):
                label = 1
                print(txt_file_name)
                break
        
        output_file = f'{label}_{txt_file_name}_{i+1}.txt'
        output_file_path = os.path.join(output_file_directory, output_file)
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        with open(output_file_path, 'w') as outfile:
            for line in lines[start:end]:
                line=line.rstrip()
                line = line.rstrip('MB')
                
                processed_line = process_line(line)
                processed_line = processed_line.replace('.', ' ').replace('/', ' ').replace('_', ' ').replace('-', ' ')
                processed_line = ' '.join(processed_line.split())    
                outfile.write(processed_line + '\n')
            outfile.write('\n')


args = parse_args()

input_csv_path = args.input_csv
output_csv_directory = args.output_csv_dir
split_csv_by_subject(input_csv_path, output_csv_directory)

csv_files = glob.glob(os.path.join(output_csv_directory, "*.csv"))

output_org_txt_directory = args.output_org_txt_dir 
output_mae_txt_directory = args.output_mae_txt_dir 

for input_csv_path in csv_files:
    file_name = os.path.basename(input_csv_path)
    txt_file_name = os.path.splitext(file_name)[0] + ".txt"
    output_org_txt_path = os.path.join(output_org_txt_directory, txt_file_name)
    output_mae_txt_path = os.path.join(output_mae_txt_directory, txt_file_name)

    os.makedirs(os.path.dirname(output_org_txt_path), exist_ok=True)
    os.makedirs(os.path.dirname(output_mae_txt_path), exist_ok=True)

    process_log(input_csv_path, output_org_txt_path, output_mae_txt_path)


output_org_txt = glob.glob(os.path.join(output_org_txt_directory, "*.txt"))
output_mae_txt = glob.glob(os.path.join(output_mae_txt_directory, "*.txt"))

output_org_txt_directory24 = args.output_split_dir 
output_mae_txt_directory24 = args.output_split_dir 

for input_file_path in output_org_txt:
    split_file_org(input_file_path,output_org_txt_directory24)

for input_file_path in output_mae_txt:
    split_file_mae(input_file_path,output_mae_txt_directory24)

