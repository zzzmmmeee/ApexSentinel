import torch
from torch.utils.data import RandomSampler, DataLoader
from torchvision import datasets, transforms
from torch.utils.tensorboard import SummaryWriter
from mae_model import MaskedAutoencoder  
import math
import argparse
def parse_args():
    parser = argparse.ArgumentParser(description="Train the Masked Autoencoder model")
    
    # 数据路径
    parser.add_argument(
        "--train_data", "-tr",
        required=True,
        help="Training data path"
    )
    parser.add_argument(
        "--val_data", "-v",
        required=True,
        help="Validation data path (val-B)"
    )
    parser.add_argument(
        "--val_data_m", "-vm",
        required=True,
        help="Validation data M path (val-M)"
    )
    
    # 模型保存路径
    parser.add_argument(
        "--model_save_path", "-m",
        required=True,
        help="Model checkpoint save path"
    )
    

args = parse_args()
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f'Using device: {device}')

model = MaskedAutoencoder().to(device)


data_path = args.train_data

transform_train = transforms.Compose([
    transforms.Grayscale(num_output_channels=1),  
    transforms.Resize((24, 128)),  
    transforms.ToTensor(),  
    transforms.Normalize((0.5,), (0.5,)),  
])

dataset_train = datasets.ImageFolder(data_path, transform=transform_train)
data_loader_train = DataLoader(
    dataset_train,
    batch_size=16,
    shuffle=True,
    num_workers=4,
    pin_memory=True,
)

def validate(model, data_loader, device):
    model.eval()
    val_loss = 0.0
    with torch.no_grad():
        for imgs, _ in data_loader:
            imgs = imgs.to(device)
            loss, _, _ = model(imgs, mask_ratio=0.6)
            val_loss += loss.item()

    val_loss /= len(data_loader)
    return val_loss

val_data_path = args.val_data
dataset_val = datasets.ImageFolder(val_data_path, transform=transform_train)
num_samples = 2000
sampler = RandomSampler(dataset_val, replacement=False, num_samples=num_samples)
data_loader_val = DataLoader(
    dataset_val,
    batch_size=16,
    sampler=sampler,
    shuffle=False,  
    num_workers=4,
    pin_memory=True,
)

val_data_path_M = args.val_data_m
dataset_val_M = datasets.ImageFolder(val_data_path_M, transform=transform_train)
data_loader_val_M = DataLoader(
    dataset_val_M,
    batch_size=16,
    shuffle=False,  
    num_workers=4,
    pin_memory=True,
)

lr_conti = 1e-3 

optimizer = torch.optim.Adam(model.parameters(), lr=lr_conti)
lr_scheduler = torch.optim.lr_scheduler.StepLR(optimizer, step_size=1, gamma=0.9)

best_val_loss = float('inf')
patience = 5  
no_improvement_counter = 0

num_epochs = 20
for epoch in range(num_epochs):
    model.train()
    for i, (imgs, _) in enumerate(data_loader_train):
        imgs = imgs.to(device)

        optimizer.zero_grad()
        loss, _, _ = model(imgs, mask_ratio=0.6)
        loss.backward()
        optimizer.step()
        
        if i % 200 == 0:
            print(f"Epoch [{epoch+1}/{num_epochs}], Step [{i+1}/{len(data_loader_train)}], Loss: {loss.item()}")

        global_step = epoch * len(data_loader_train) + i
        #log_writer.add_scalar('train_loss', loss.item(), global_step)
        #log_writer.add_scalar('learning_rate', optimizer.param_groups[0]['lr'], global_step)

    val_loss = validate(model, data_loader_val, device)
    print(f"Epoch [{epoch+1}/{num_epochs}], Validation Loss: {val_loss}")

    val_loss_M = validate(model, data_loader_val_M, device)
    print(f"Epoch [{epoch+1}/{num_epochs}], Validation M Loss: {val_loss_M}")

    lr_scheduler.step()

    if val_loss < best_val_loss:
        best_val_loss = val_loss
        no_improvement_counter = 0
        checkpoint = {
            'model_state_dict': model.state_dict(),
            'optimizer_state_dict': optimizer.state_dict(),
            'epoch': epoch,
            'global_step': global_step
        }
        torch.save(checkpoint, args.model_save_path)  
    else:
        no_improvement_counter += 1

    if no_improvement_counter >= patience:
        print("Stopping early due to no improvement in validation loss.")
        break



print("Training complete.")
