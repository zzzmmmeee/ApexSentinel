import os
import shutil
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Filter TXT files")
    
    parser.add_argument(
        "--source_folder", "-s",
        required=True,
        help="Source folder path (i.e., output_org_txt_directory24, storing split raw data)"
    )
    parser.add_argument(
        "--target_folder", "-t",
        required=True,
        help="Target folder path, storing filtered txt files"
    )
    parser.add_argument(
        "--loss_file", "-l",
        required=True,
        help="Path to the loss.txt file"
    )
    parser.add_argument(
        "--filtered_txt", "-f",
        required=True,
        help="Output path for the filtered and re-sorted txt file"
    )
    
    return parser.parse_args()
def filter_files(source_folder, target_folder, loss_file, loss_threshold=0.012):
    with open(loss_file, 'r') as file:
        for line in file:
            parts = line.split(", Loss: ")
            file_name = parts[0]
            loss = float(parts[1])
            
            if loss > loss_threshold and file_name.endswith(".txt.png"):
                txt_file_name = file_name.replace(".png", "")
                source_file_path = os.path.join(source_folder, txt_file_name)
                target_file_path = os.path.join(target_folder, txt_file_name)
                
                if os.path.exists(source_file_path):
                    shutil.copy(source_file_path, target_file_path)
                    print(f"Copied {txt_file_name} to {target_folder}")
                else:
                    print(f"File {txt_file_name} does not exist in the source folder.")

def reorder(log_files_directory, filtered_txt):
    log_files = [f for f in os.listdir(log_files_directory) if f.endswith('.txt')]
    all_logs = []

    for file in log_files:
        with open(os.path.join(log_files_directory, file), 'r') as f:
            for line in f:
                line = line.rstrip('\n')
                if line.strip():
                    all_logs.append(line)

    all_logs = [log for log in all_logs if log.split()[0].isdigit()]
    all_logs.sort(key=lambda x: int(x.split()[0]))

    with open(filtered_txt, 'w') as sorted_file:
        for log in all_logs:
            sorted_file.write(log + '\n')


if __name__ == "__main__":
    args = parse_args()
    source_folder = args.source_folder
    target_folder = args.target_folder
    loss_file = args.loss_file
    filtered_txt = args.filtered_txt

    if not os.path.exists(target_folder):
        os.makedirs(target_folder)

    filter_files(source_folder, target_folder, loss_file)

    reorder(target_folder, filtered_txt)