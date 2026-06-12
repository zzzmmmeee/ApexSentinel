# ApexSentinel

## Environment Settings
```bash
conda create -n apexsentinel python=3.11 -y
conda activate apexsentinel
pip install -r requirements.txt
```
## Datasets preparation
We have provided the pruned log data in `./dataset`. You can also download the DARPA TC dataset from: https://drive.google.com/drive/folders/1fOCY3ERsEmXmvDekG-LUUSjfWs6TRdp- and refer to the code in `./MAElog` to filter the original log files.

## Run
### Cadets dataset
For cadets dataset, in `config.py` set:
```python
theia = 0 
```
Run the detection script:
```bash
python testLLM.py --multi_dir ./dataset/split_cadets
```

### Theia dataset
For theia dataset, in `config.py` set:
```python
theia = 1 
```
Run the detection script:
```bash
python testLLM.py --multi_dir ./dataset/split_theia
```

### Evaluation
```bash
python evaluate_window_detection.py --alert_path ./result
```