prompt_tokens = 0
output_tokens = 0

def add_prompt(n: int):
    global prompt_tokens
    prompt_tokens += n

def add_output(n: int):
    global output_tokens
    output_tokens += n

def add(prompt_n: int, output_n: int):
    add_prompt(prompt_n)
    add_output(output_n)

def reset():
    global prompt_tokens, output_tokens
    prompt_tokens = 0
    output_tokens = 0

def get_prompt():
    return prompt_tokens

def get_output():
    return output_tokens

def get_total():
    return prompt_tokens + output_tokens