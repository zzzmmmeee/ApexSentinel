import torch
from torch.utils.data import DataLoader, Dataset
from torchvision import datasets, transforms
from PIL import Image
from tqdm import tqdm
import numpy as np
import os
from mae_model import MaskedAutoencoder
import random
import time
import thop

class CustomDataset(Dataset):
    def __init__(self, root_dir, transform=None):
        random.seed(42)  
        self.root_dir = root_dir
        self.transform = transform
        
        #self.file_names = random.sample([f for f in os.listdir(data_path) if os.path.isfile(os.path.join(data_path, f))], 2631)#4671 2631 1806
        self.file_names = [f for f in os.listdir(root_dir) if os.path.isfile(os.path.join(root_dir, f))] # random.sample([f for f in os.listdir(data_path) if os.path.isfile(os.path.join(data_path, f))], 300)
    def __len__(self):
        return len(self.file_names)

    def __getitem__(self, idx):
        img_name = self.file_names[idx]
        img_path = os.path.join(self.root_dir, img_name)
        image = Image.open(img_path).convert('L')
        if self.transform:
            image = self.transform(image)
        return image, img_name

def mae_test(mae_model_path, data_path, loss_file):
    
    model = MaskedAutoencoder()
    checkpoint = torch.load(mae_model_path)
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()

    transform_test = transforms.Compose([
        transforms.Grayscale(num_output_channels=1),
        transforms.Resize((24, 128)),
        transforms.ToTensor(),
        transforms.Normalize((0.5,), (0.5,))
    ])

    dataset_test = CustomDataset(data_path, transform=transform_test)

    data_loader_test = DataLoader(
        dataset_test,
        batch_size=8,
        drop_last=False
    )

    data_loader_test = tqdm(data_loader_test, desc="Testing")
    num_batches = len(data_loader_test)
    print(num_batches)

    start_time = time.time()
    print(start_time)

    with torch.no_grad():
        with open(loss_file, 'a') as f:
            for batch_idx, (imgs, img_names) in enumerate(data_loader_test):
                _, _, loss = model(imgs, mask_ratio=0.6)
                for img_name, img_loss in zip(img_names, loss):
                    f.write(f"{img_name}, Loss: {img_loss:.5f}\n")

    end_time = time.time()
    print(end_time)
    processing_time = end_time - start_time
    print(f"Processing Time: {processing_time} seconds")
    print("Testing complete.")
