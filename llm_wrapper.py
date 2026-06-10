# coding=utf-8
import sys
sys.path.append('/home/wucanyang')
import os
os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"
os.environ['PYTORCH_CUDA_ALLOC_CONF'] = 'expandable_segments:True'
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
from token_count import add

class LLMModel:
    def __init__(self, model_name="Qwen/Qwen2.5-32B-Instruct"):
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForCausalLM.from_pretrained(
            model_name,
            torch_dtype="auto",
            device_map="auto"
        )
        self.history = None

    def query(self, prompt):
        messages = [{"role": "user", "content": prompt}]
        text = self.tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True
        )
        model_inputs = self.tokenizer([text], return_tensors="pt").to(self.model.device)

        generated_ids = self.model.generate(
            **model_inputs,
            max_new_tokens=1024
        )
        generated_ids = [
            output_ids[len(input_ids):] for input_ids, output_ids in zip(model_inputs.input_ids, generated_ids)
        ]

        response = self.tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]

        # prompt tokens
        prompt_tokens = model_inputs.input_ids.shape[-1]

        # response tokens
        response_tokens = generated_ids[0].shape[-1]
        add(prompt_tokens, response_tokens)

        return response

    def reset_history(self):
        self.history = None