import numpy as np
import os
from PIL import Image
import glob
from gensim.models import Word2Vec
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Convert TXT logs to grayscale images")
    
    parser.add_argument(
        "--txt_path", "-i",
        required=True,
        help="TXT file path (folder containing 24-line split files, i.e., output_mae_txt_directory24)"
    )
    parser.add_argument(
        "--out_path", "-o",
        required=True,
        help="Save path for grayscale images"
    )
    
    return parser.parse_args()


def read_logs(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

def extract_features(logs):
    vectors = []

    for line in logs:
        line = line.strip().replace('_', ' ').replace('/', ' ').replace('\\', ' ').replace('.', ' ').replace(';', ' ').replace('"', ' ')
        words = line.split()  
        word_vectors = []
        
        for word in words:
            if word in model.wv.key_to_index:  
                word_vector = model.wv[word]  
                word_vectors.append(word_vector)

        line_vector = [item for sublist in word_vectors for item in sublist]
        
        if len(line_vector) < 128:
            line_vector.extend([0] * (128 - len(line_vector)))
        elif len(line_vector) > 128:
            line_vector = line_vector[:128]
        
        vectors.append(line_vector)

    features = [vector for vector in vectors]

    transformed_features=np.array(features)

    min_val = np.min(transformed_features) 
    max_val = np.max(transformed_features)
    normalized_features = (transformed_features - min_val) / (max_val - min_val)
    return normalized_features

def feature_normalize(features):
    min_val = np.min(features)
    max_val = np.max(features)
    normalized_features = (features - min_val) / (max_val - min_val)
    return normalized_features


def features_to_gray_image(normalized_features,txt_file, out_path):
    txt_file = os.path.basename(txt_file)
    fh = (normalized_features * 255).astype(np.uint8)
    #print(normalized_features.shape)
    im = Image.fromarray(fh)
    filename = f'{txt_file}.png'

    output_file = os.path.join(out_path, filename)

    im.save(output_file)



model = Word2Vec.load('logvec.model')

args = parse_args()
txt_path = args.txt_path
out_path = args.out_path
os.makedirs(os.path.dirname(out_path), exist_ok=True)

txt_files = [os.path.join(txt_path, f) for f in os.listdir(txt_path) if f.endswith('.txt')]

for txt_file in txt_files:

    logs = read_logs(txt_file)
    
    features = extract_features(logs[:24])
        
    features_to_gray_image(features,txt_file, out_path)


print('feature-success')

