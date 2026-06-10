from llm_wrapper import LLMModel  
from log_utils import extract_logs_from_graph,check_community_relation 
from collections import defaultdict
import re
import json
from collections import Counter
import signal
from typing import List
from typing import Optional
from token_count import add
import config

class TimeoutException(Exception):
    pass

def timeout_wrapper(func, args=(), kwargs={}, timeout=180, default=None):
    def handler(signum, frame):
        raise TimeoutException("Model inference timed out")

    signal.signal(signal.SIGALRM, handler)
    signal.alarm(timeout)

    try:
        result = func(*args, **kwargs)
        signal.alarm(0)
        return result
    except TimeoutException:
        print("The community analysis model call timed out, skipping.")
        return default
    
if config.theia == 0:
    MAX_LOG_LINES_PER_SEGMENT = 50  
else:
    MAX_LOG_LINES_PER_SEGMENT = 100  


def safe_json_parse(json_like_str):
    json_like_str = json_like_str.replace('“', '"').replace('”', '"') \
                                 .replace('‘', '"').replace('’', '"') \
                                 .replace('：', ':').replace('，', ',')   
    json_like_str = re.sub(r'"(\w+)"\s+([\"\[{]?\w+)', r'"\1": \2', json_like_str)
    json_like_str = re.sub(r',\s*([\]}])', r'\1', json_like_str)

    try:
        return json.loads(json_like_str)
    except json.JSONDecodeError as e:
        print("JSON修复失败：", e)
        print("原始/修复内容如下：\n", json_like_str)
        return None


def summarize_behavior(log_lines: List[str]) -> str:
    counter = Counter(log_lines)

    # 保持原始顺序去重合并
    seen = set()
    summarized = []
    for line in log_lines:
        if line not in seen:
            seen.add(line)
            count = counter[line]
            if count > 1:
                summarized.append(f"{line} (×{count})")
            else:
                summarized.append(line)

    return "\n".join(summarized)

_event_pat = re.compile(r'\b(aue_open_rwtc|aue_fchdir|aue_close)\b')
_proc_pat  = re.compile(r'\b([A-Za-z0-9._-]+)\s+(aue_open_rwtc|aue_fchdir|aue_close)\b')

def extract_event(line: str) -> Optional[str]:
    m = _event_pat.search(line)
    return m.group(1) if m else None

def extract_proc(line: str) -> Optional[str]:
    m = _proc_pat.search(line)
    return m.group(1) if m else None

def extract_path(line: str) -> str:
    return line.rsplit(maxsplit=1)[-1]

def compress_open_modify_close(log_lines: List[str]) -> List[str]:
    compressed: List[str] = []
    i = 0
    while i < len(log_lines):
        if i + 2 < len(log_lines):
            e1 = extract_event(log_lines[i])
            e2 = extract_event(log_lines[i + 1])
            e3 = extract_event(log_lines[i + 2])

            if e1 == "aue_open_rwtc" and e2 == "aue_fchdir" and e3 == "aue_close":
                p1 = extract_path(log_lines[i])
                p2 = extract_path(log_lines[i + 1])
                p3 = extract_path(log_lines[i + 2])

                if p1 == p2 == p3:
                    proc = extract_proc(log_lines[i]) or "<unknown>"
                    compressed.append(f"{proc} open→fchdir→close {p1}")
                    i += 3
                    continue

        compressed.append(log_lines[i])
        i += 1

    return compressed

def analyze_long_process(process, log_lines, llm_model):
    highest_suspicion = 0.0  
    best_summary = ""  
    
    for i in range(0, len(log_lines), MAX_LOG_LINES_PER_SEGMENT): 
        segment = log_lines[i:i + MAX_LOG_LINES_PER_SEGMENT]
        # You are a security analyst. The following is a partial event sequence of a process in the system log:
        segment_prompt = f"你是一位安全分析师，以下是系统日志中某一个进程 {process} 的部分事件序列：\n" + "\n".join(segment) 
        if config.theia == 0:
            segment_prompt += """
请执行以下任务：
        1. 分析此进程的时间序列，将进程的行为总结为一句话，注意保留关键内容和关键文件名/套接字等，但是不需要额外的推测。
        2. 根据你的总结，请以安全分析师的角度，分析这个进程的行为是否可能为高级持续性威胁（APT）攻击的一部分。

        请注意，以下行为应视为系统正常或低风险流程(可疑度分数<=0.3)：
        [
            {
                "名称": "pkg 标准软件包管理行为",
                "特征": "SUBJECT_PROCESS 为 'pkg'；包含三种标准操作模式：1) OPEN→READ→CLOSE 文件操作（访问/var/db/pkg/*.sqlite、/etc/pkg/*.conf等标准路径，mode≤5）；2) FCNTL 控制命令与SQLite交互（数据量≤4KB/次，含合法journal操作）；3) OPEN→MMAP→CLOSE 配置加载（映射1-8MB标准配置文件）；均使用aue_pread/aue_openat_rwtc等标准IO方法，且无execve/connect/chmod等高危调用",
                "理由": "完整涵盖pkg包管理器的常规操作：数据库维护（含事务处理）、配置加载和文件访问，所有行为均符合FreeBSD/OpenBSD系统设计规范，长期观测中表现出稳定、低风险特性"
            },
            {
                "名称": "pkg 常规元数据写入操作",
                "特征": "SUBJECT_PROCESS 为 'pkg'；操作类型为连续 WRITE 事件；调用方法为 aue_write；目标文件标识符稳定（BF253D48-3E05-11E8-A5CB-3FA3753A265A）；单次写入量≤35B；写入模式呈现规律性循环（4B→6B→2B→35B）；无文件路径修改或权限变更行为",
                "理由": "该模式符合软件包管理器维护元数据文件的典型特征，表现为小数据量、周期性、固定格式的写入行为，常见于数据库索引更新或状态记录场景，属于低风险系统维护操作"
            },
            {
                "名称": "交互式终端会话",
                "特征": "频繁交替调用对 /dev/tty 的 READ 和 WRITE 系统调用，字节数较小（1-8 字节）",
                "理由": "典型的用户终端交互行为，不属于恶意操作"
            },
            {
                "名称": "alpine 邮件客户端正常行为",
                "特征": "进程名为 'alpine'，行为包括用户识别、配置加载、终端交互、邮件读取与草稿写入等。调用序列规范，主要包含 aue_read 与 aue_write 操作 /dev/tty，以及对 /home/user/#pico* 草稿文件的 OPEN、WRITE、TRUNCATE、CLOSE 操作。无 execve、connect、chmod 等高危系统调用，路径正常，无越权访问",
                "理由": "该行为为典型的终端邮件客户端使用流程，符合用户主动操作特征，长期观察中稳定，属于低风险行为"
            },
            {
                "名称": "Cron 作业调度任务执行",
                "特征": "由cron启动sh子进程执行固定命令；依次访问 /etc/spwd.db、/etc/login.conf、/etc/group 等配置文件；通过unix socket与 /var/run/logpriv 通信；无异常系统调用，权限变更合理、无外部连接",
                "理由": "符合 FreeBSD 下 cron 计划任务执行的标准初始化与环境加载流程"
            },
            {
                "名称": "Atrun 执行 at 计划任务",
                "特征": "由 atrun 程序按时唤起，访问 libmap.conf、ld-elf.so.hints 及多种系统库文件（如 libc.so、libpam.so）；加载动态链接库并切换目录至 /var/at/jobs/；行为中无 exec、网络连接、权限异常或异常路径",
                "理由": "符合系统 at 任务调度组件 atrun 的常规运行逻辑"
            },
            {
                "名称": "低风险 top 系统监控行为",
                "特征": "进程名为 'top'，由 bash 执行启动；其行为包括读取 libmap.conf、nsswitch.conf、pwd.db 等系统配置与用户信息文件，加载常规动态链接库（如 libncursesw、libm、libelf），并通过 mmap 进行内存映射；无写入操作，无网络连接、权限变更或进程控制行为",
                "理由": "top 是标准的系统资源查看工具，该行为符合典型终端交互使用情形，调用序列稳定、无可疑外联与破坏性操作，判定为低风险"
            },
            {
                "名称": "sshd 启动登录会话的正常行为",
                "特征": "进程名为 'sshd'，执行 CHANGE_PRINCIPAL（aue_seteuid, aue_setegid）、chdir、execve 启动用户 shell（如 bash），并读取 login.conf、.login_conf 等配置文件。行为中无可疑写入、连接、权限修改，路径规范",
                "理由": "该行为是 SSH 登录后切换用户、加载配置并启动 shell 的标准流程，系统调用序列常见于用户远程登录初始化阶段，稳定、无越权行为，判定为低风险"
            },
            {
                "名称": "本地邮件发送",
                "特征": "sendmail 使用 127.0.0.1 回环地址与本地 SMTP 端口通信，无外联",
                "理由": "正常本地邮件传递行为，不涉及数据外泄"
            },
            {
                "名称": "标准系统调用",
                "特征": "仅使用常见的 open、read、write、lseek、fcntl、close、fork 等系统调用",
                "理由": "未出现执行类（exec）或网络连接类（connect/sendto）等高风险操作"
            },
            {
                "名称": "低风险 wget 下载初始化行为",
                "特征": "进程名为 'wget'，由 shell 启动后加载 libintl、libunistring、libidn2、libssl、libcrypto 等常用库，读取 /etc/libmap.conf 和 /var/run/ld-elf.so.hints 以完成动态链接，访问配置文件 /usr/local/etc/wgetrc，期间无 connect/sendto、chmod、unlink 等高危调用",
                "理由": "该行为属于 wget 工具正常初始化加载共享库与配置阶段，无实际发起连接行为，无路径异常或权限操作，判定为低风险（仅限未发起网络通信时）"
            },
            {
                "名称": "低风险 find 扫描",
                "特征": "SUBJECT_PROCESS 为 \"find\" 或 \"sh;find\"；仅包含 OPEN(aue_open_rwtc)、CLOSE(aue_close)、MODIFY_PROCESS(aue_fchdir) 事件组合；文件访问模式 ≤5（只读目录遍历）；路径不含 passwd、shadow、ssh 等敏感关键字；调用序列未出现删除/重命名/权限修改/execve 等高风险事件，亦无写入或属性修改",
                "理由": "find 仅进行递归只读遍历目录树，不修改文件或系统状态，属正常运维或用户查询操作，可视为低风险"
            },
            {
                "名称": "低风险 shell 目录遍历",
                "特征": "SUBJECT_PROCESS 为 \"sh;...\"，事件仅包含 OPEN(aue_open_rwtc) → MODIFY_PROCESS(aue_fchdir) → CLOSE(aue_close) 循环；mode ≤5；路径无敏感关键字；序列中无写入、删除、权限修改、execve、网络连接等高风险系统调用",
                "理由": "shell 脚本或交互命令仅在做只读目录递归或文件枚举，不改变系统状态、不外联，可视为低风险"
            },
            {
                "名称": "fortune 只读命令执行",
                "特征": "执行 /usr/bin/fortune，仅读取系统配置文件和游戏数据；调用 mmap 加载共享库，无写操作、无外联、无权限变更",
                "理由": "典型只读工具行为，无风险操作"
            },
            {
                "名称": "inetd管理网络连接，并启动相应的imapd服务进行读写操作",
                "特征": "inetd（网络守护进程）接受了传入的网络连接，并通过 FORK 操作创建子进程来处理这些连接，具体为 imapd 服务，即 imapd 守护进程一系列读写操作，可视为低风险,
                "理由": "无风险操作"
            }
        ]
        
        给出可疑度分数，评分范围为：0~0.3（正常或低风险）；0.3~0.8（中等风险，需进一步调查）；0.8~1（高风险，需立即处置）
        只给出严格 JSON 输出（不要任何额外文本、不要代码块），示例输出格式:
        {
            "行为总结": "进程 X 执行多个未经授权的文件修改",
            "可疑度分数": 0.95
        }
        注意：若包含文件路径，请将反斜杠双写为 \\\\，或改用正斜杠 /

            """    
        else:
            segment_prompt += """
        请执行以下任务：
        1. 分析此进程的时间序列，将进程的行为总结为一句话，注意保留关键内容和关键文件名/套接字等，但是不需要额外的推测。
        2. 根据你的总结，请以安全分析师的角度，分析这个进程的行为是否可能为高级持续性威胁（APT）攻击的一部分。
        给出可疑度分数，评分范围为：0~0.3（正常或低风险）；0.3~0.8（中等风险，需进一步调查）；0.8~1（高风险，需立即处置）

        请注意，以下行为应视为系统正常或低风险流程(可疑度分数<=0.3)：
        [
            {
                "名称": "fluxbox 被动事件接收行为",
                "特征": "SUBJECT_PROCESS 为 'fluxbox'；行为仅包含连续大量 EVENT_RECVFROM 事件；事件通信对象交替为 'NetFlowObject' 和 'unknown'；每对事件共享同一时间戳；频率高、时间间隔短；未包含 WRITE、OPEN、EXECUTE、CONNECT 等主动调用",
                "理由": "该行为符合图形窗口管理器 fluxbox 在图形会话中被动监听系统事件、输入消息或图形层通知的特征。事件中对象不明确但行为极为稳定，表现为典型的图形环境中的消息轮询或事件广播处理流程。行为不涉及任何系统状态修改或安全敏感操作，判定为低风险（可疑度 ≤ 0.3）"
            },
            {
                "名称": "fluxbox 图形窗口管理器的被动通信行为",
                "特征": "SUBJECT_PROCESS 为 'fluxbox'；行为为大量 EVENT_RECVFROM 事件；来源对象名称为 NetFlowObject 或 unknown，事件总是成对出现；事件时间戳极为接近（间隔小于几百微秒）；未伴随 OPEN、WRITE、EXECUTE、CONNECT、MODIFY_PROCESS 等高风险操作",
                "理由": "该行为模式为图形窗口管理器在图形会话中的被动监听行为，接收系统广播事件或底层通信通知。通信对象虽未知但行为高度一致、重复出现、且未观察到主动系统操作，属于低风险监听机制，无需判定为可疑（建议可疑度 ≤ 0.3）"
            },
            {
                "名称": "sshd 合法远程登录与交互行为",
                "特征": "SUBJECT_PROCESS 为 'sshd: <user> [priv]'；包含交替出现的 READ_SOCKET_PARAMS / WRITE_SOCKET_PARAMS / RECVMSG / CLONE 等事件；通信对象为 NetFlowObject 与 unknown 的成对结构；可能涉及对 /dev/ptmx 的 READ 和 WRITE 操作；过程最后出现子进程 fork（EVENT_CLONE）并建立 tty 会话；无 chmod、exec 非法路径、suid 提权等异常操作",
                "理由": "该行为是标准 SSH 登录过程中的服务端处理逻辑，包括 socket 参数读取、终端绑定、数据收发以及创建交互式 shell 子进程。日志中无外联异常、无多主机横跳、无非法文件访问，连接 IP 合法（若可验证）、路径规范、无权限操作，符合 OpenSSH 的典型实现，判定为低风险（可疑度 ≤ 0.2）"
            },
            {
                "名称": "sshd 用户终端子会话交互行为",
                "特征": "SUBJECT_PROCESS 为 'sshd: <user>@pts/<n>'；事件以 OPEN 和 WRITE 交替访问 /dev/null 为主；每对 OPEN/WRITE 操作对象均为 /dev/null，表现为规律性重复写入；事件对象名为 FILE_OBJECT_BLOCK 或 unknown；无权限修改、无执行行为、无文件写入其他路径",
                "理由": "该行为代表用户登录 SSH 后建立交互式 shell（如 bash、sh），其输出或日志被重定向至 /dev/null，是标准的终端初始化或后台任务控制逻辑。无路径异常、无权限操作、系统调用模式稳定，符合安全终端会话的典型特征，属于低风险行为（可疑度 ≤ 0.2）"
            },
            {
                "名称": "ELF 动态链接库加载与内存映射行为",
                "特征": "SUBJECT_PROCESS 可为空或为常见前台/后台进程；事件序列包含 OPEN → READ → MMAP → MPROTECT 操作；路径为 /usr/lib/x86_64-linux-gnu/*.so.* 形式的共享库；事件对象多为 MemoryObject 和 FILE_OBJECT_BLOCK；可出现 unknown 标记对象但未配套高风险系统调用；行为高频、序列规则、路径受控",
                "理由": "该行为是 ELF 可执行文件在加载共享库时的标准行为流程，包括对动态链接库文件的打开、读取、内存映射以及可执行权限设定（mprotect），这些操作广泛出现在几乎所有运行中用户进程中，属于 Linux 的正常加载机制。行为路径规范、调用序列标准、无写入或执行风险，判定为低风险（可疑度 ≤ 0.2）"
            }
        ]

       
        只给出严格 JSON 输出（不要任何额外文本、不要代码块），示例输出格式:
        {
            "行为总结": "进程 X 执行多个未经授权的文件修改",
            "可疑度分数": 0.95
        }
        注意：若包含文件路径，请将反斜杠双写为 \\\\，或改用正斜杠 /
            """    
        print(segment_prompt)
        response = llm_model.query(segment_prompt)
        print(response)
        #prompt_tokens = len(llm_model.tokenizer.encode(segment_prompt, add_special_tokens=False))
        #response_tokens = len(llm_model.tokenizer.encode(response, add_special_tokens=False))
        #add(prompt_tokens, response_tokens)

        match = re.search(r'{.*}', response, re.DOTALL)
    
        if match:
            json_str = match.group(0)
            try:
                response_data = json.loads(json_str)
                suspicion_score = response_data["可疑度分数"]
                summary = response_data["行为总结"]
                
                if suspicion_score > highest_suspicion:
                    highest_suspicion = suspicion_score
                    best_summary = summary

            except json.JSONDecodeError as e:
                print("JSON 解析错误:", e)
        else:
            print("未找到 JSON 格式的数据")
            continue  

    return json.dumps({
        "行为总结": best_summary,
        "可疑度分数": highest_suspicion
    })


def analyze_process_patterns(community, llm_model):
    temporal_patterns = {}
    process_scores = {}
    suspicious_processes = []
    logs_by_source = extract_logs_from_graph(community)

    for source, logs in logs_by_source.items():
        if 'properties_map_exec' not in logs[0]['source'][1]:
            process = "unknown process"
        else:
            process = logs[0]['source'][1]['properties_map_exec']
        
        prompt = f"""
        你是一位安全分析师，以下是系统日志中某一个进程 {process} 的部分事件序列:

        """
        
        if config.theia == 0:
            log_lines = [
                f"{process} {log['action']} {log['target'][1]['target_object_path']}"#({log['target'][1]['type']})" 
                for log in logs
            ]
        else:
            log_lines = [
                f"{process} {log['action']} {log['target'][1]['target_object_path']}({log['target'][1]['type']})" 
                for log in logs
            ]
        
        if len(logs) <=3:
             print("进程日志条数过少，需要进一步进行社区内的关联分析")
             suspicious_processes.append(source)
             temporal_patterns[source] = "\n".join(log_lines)
             continue
        
        # 使用压缩版日志
        log_lines = compress_open_modify_close(log_lines)

        if len(log_lines) > MAX_LOG_LINES_PER_SEGMENT:
            response = analyze_long_process(process, log_lines, llm_model)
        else:
            prompt_logs = summarize_behavior(log_lines)
            prompt += prompt_logs
            if config.theia == 0:
                prompt += """
                请执行以下任务：
                1. 分析此进程的时间序列，将进程的行为总结为一句话，注意保留关键内容和关键文件名/套接字等，但是不需要额外的推测。
                2. 根据你的总结，请以安全分析师的角度，分析这个进程的行为是否可能为高级持续性威胁（APT）攻击的一部分。
                给出可疑度分数，评分范围为：0~0.3（正常或低风险）；0.3~0.8（中等风险，需进一步调查）；0.8~1（高风险，需立即处置）

                请注意，以下行为应视为系统正常或低风险流程(可疑度分数<=0.3)：
                [
                    {
                        "名称": "pkg 标准软件包管理行为",
                        "特征": "SUBJECT_PROCESS 为 'pkg'；包含三种标准操作模式：1) OPEN→READ→CLOSE 文件操作（访问/var/db/pkg/*.sqlite、/etc/pkg/*.conf等标准路径，mode≤5）；2) FCNTL 控制命令与SQLite交互（数据量≤4KB/次，含合法journal操作）；3) OPEN→MMAP→CLOSE 配置加载（映射1-8MB标准配置文件）；均使用aue_pread/aue_openat_rwtc等标准IO方法，且无execve/connect/chmod等高危调用",
                        "理由": "完整涵盖pkg包管理器的常规操作：数据库维护（含事务处理）、配置加载和文件访问，所有行为均符合FreeBSD/OpenBSD系统设计规范，长期观测中表现出稳定、低风险特性"
                    },
                    {
                        "名称": "pkg 常规元数据写入操作",
                        "特征": "SUBJECT_PROCESS 为 'pkg'；操作类型为连续 WRITE 事件；调用方法为 aue_write；目标文件标识符稳定（BF253D48-3E05-11E8-A5CB-3FA3753A265A）；单次写入量≤35B；写入模式呈现规律性循环（4B→6B→2B→35B）；无文件路径修改或权限变更行为",
                        "理由": "该模式符合软件包管理器维护元数据文件的典型特征，表现为小数据量、周期性、固定格式的写入行为，常见于数据库索引更新或状态记录场景，属于低风险系统维护操作"
                    }
                    {
                        "名称": "Cron 启动的 Atrun 执行 at 任务",
                        "特征": "SUBJECT_PROCESS 为 'cron'，后跟 sh 启动 /usr/libexec/atrun；访问 /etc/spwd.db、/etc/login.conf、/etc/group、/etc/pwd.db 等文件；权限变更包括 setgid、setuid、seteuid、umask；切换目录至 /root；通过 /var/run/logpriv unix socket 日志通信；无外部网络连接，无可疑写入或异常执行路径",
                        "理由": "行为链完整、顺序规范，符合计划任务通过 atrun 执行的标准流程，未出现超权限访问、未知路径或代码注入等特征，应视为可信行为"
                    },
                    {
                        "名称": "Postfix 正常本地投递流程",
                        "特征": "SUBJECT_PROCESS 为 'local'；行为包含 setegid/seteuid 权限调整、UNLINK 邮箱锁、发送日志至 /var/run/logpriv；伴随访问 /etc/services、/etc/hosts、/etc/resolv.conf 等配置文件；无异常文件路径，无 execve、chmod、connect 外部地址、权限异常；访问 active/ 邮件队列路径并写入，表现为正常邮件投递处理",
                        "理由": "该行为符合 FreeBSD 下 postfix 本地邮件传送代理 'local' 的投递流程，涉及权限调整、日志记录与读取标准配置，无异常访问行为，长期观察中为低风险、常规操作模式"
                    },
                    {
                        "名称": "交互式终端会话",
                        "特征": "频繁交替调用对 /dev/tty 的 READ 和 WRITE 系统调用，字节数较小（1-8 字节）",
                        "理由": "典型的用户终端交互行为，不属于恶意操作"
                    },
                    {
                        "名称": "alpine 邮件客户端正常行为",
                        "特征": "进程名为 'alpine'，行为包括用户识别、配置加载、终端交互、邮件读取与草稿写入等。调用序列规范，主要包含 aue_read 与 aue_write 操作 /dev/tty，以及对 /home/user/#pico* 草稿文件的 OPEN、WRITE、TRUNCATE、CLOSE 操作。无 execve、connect、chmod 等高危系统调用，路径正常，无越权访问",
                        "理由": "该行为为典型的终端邮件客户端使用流程，符合用户主动操作特征，长期观察中稳定，属于低风险行为"
                    },
                    {
                        "名称": "Cron 作业调度任务执行",
                        "特征": "由cron启动sh子进程执行固定命令；依次访问 /etc/spwd.db、/etc/login.conf、/etc/group 等配置文件；通过unix socket与 /var/run/logpriv 通信；无异常系统调用，权限变更合理、无外部连接",
                        "理由": "符合 FreeBSD 下 cron 计划任务执行的标准初始化与环境加载流程"
                    },
                    {
                        "名称": "Atrun 执行 at 计划任务",
                        "特征": "由 atrun 程序按时唤起，访问 libmap.conf、ld-elf.so.hints 及多种系统库文件（如 libc.so、libpam.so）；加载动态链接库并切换目录至 /var/at/jobs/；行为中无 exec、网络连接、权限异常或异常路径",
                        "理由": "符合系统 at 任务调度组件 atrun 的常规运行逻辑"
                    },
                    {
                        "名称": "低风险 top 系统监控行为",
                        "特征": "进程名为 'top'，由 bash 执行启动；其行为包括读取 libmap.conf、nsswitch.conf、pwd.db 等系统配置与用户信息文件，加载常规动态链接库（如 libncursesw、libm、libelf），并通过 mmap 进行内存映射；无写入操作，无网络连接、权限变更或进程控制行为",
                        "理由": "top 是标准的系统资源查看工具，该行为符合典型终端交互使用情形，调用序列稳定、无可疑外联与破坏性操作，判定为低风险"
                    },
                    {
                        "名称": "sshd 启动登录会话的正常行为",
                        "特征": "进程名为 'sshd'，执行 CHANGE_PRINCIPAL（aue_seteuid, aue_setegid）、chdir、execve 启动用户 shell（如 bash），并读取 login.conf、.login_conf 等配置文件。行为中无可疑写入、连接、权限修改，路径规范",
                        "理由": "该行为是 SSH 登录后切换用户、加载配置并启动 shell 的标准流程，系统调用序列常见于用户远程登录初始化阶段，稳定、无越权行为，判定为低风险"
                    },
                    {
                        "名称": "低风险 wget 下载初始化行为",
                        "特征": "进程名为 'wget'，由 shell 启动后加载 libintl、libunistring、libidn2、libssl、libcrypto 等常用库，读取 /etc/libmap.conf 和 /var/run/ld-elf.so.hints 以完成动态链接，访问配置文件 /usr/local/etc/wgetrc，期间无 connect/sendto、chmod、unlink 等高危调用",
                        "理由": "该行为属于 wget 工具正常初始化加载共享库与配置阶段，无实际发起连接行为，无路径异常或权限操作，判定为低风险（仅限未发起网络通信时）"
                    },
                    {
                        "名称": "本地邮件发送",
                        "特征": "sendmail 使用 127.0.0.1 回环地址与本地 SMTP 端口通信，无外联",
                        "理由": "正常本地邮件传递行为，不涉及数据外泄"
                    },
                    {
                        "名称": "标准系统调用",
                        "特征": "仅使用常见的 open、read、write、lseek、fcntl、close、fork 等系统调用",
                        "理由": "未出现执行类（exec）或网络连接类（connect/sendto）等高风险操作"
                    },
                    {
                        "名称": "低风险 find 扫描",
                        "特征": "SUBJECT_PROCESS 为 \"find\" 或 \"sh;find\"；仅包含 OPEN(aue_open_rwtc)、CLOSE(aue_close)、MODIFY_PROCESS(aue_fchdir) 事件组合；文件访问模式 ≤5（只读目录遍历）；路径不含 passwd、shadow、ssh 等敏感关键字；调用序列未出现删除/重命名/权限修改/execve 等高风险事件，亦无写入或属性修改",
                        "理由": "find 仅进行递归只读遍历目录树，不修改文件或系统状态，属正常运维或用户查询操作，可视为低风险"
                    },
                    {
                        "名称": "低风险 shell 目录遍历",
                        "特征": "SUBJECT_PROCESS 为 \"sh;...\"，事件仅包含 OPEN(aue_open_rwtc) → MODIFY_PROCESS(aue_fchdir) → CLOSE(aue_close) 循环；mode ≤5；路径无敏感关键字；序列中无写入、删除、权限修改、execve、网络连接等高风险系统调用",
                        "理由": "shell 脚本或交互命令仅在做只读目录递归或文件枚举，不改变系统状态、不外联，可视为低风险扫描"
                    },
                    {
                        "名称": "inetd管理网络连接，并启动相应的imapd服务进行读写操作",
                        "特征": "inetd（网络守护进程）接受了传入的网络连接，并通过 FORK 操作创建子进程来处理这些连接，具体为 imapd 服务，即 imapd 守护进程一系列读写操作，可视为低风险,
                        "理由": "无风险操作"
                    }
                ]

                只给出严格 JSON 输出（不要任何额外文本、不要代码块），示例输出格式:
                {
                    "行为总结": "进程 X 执行多个未经授权的文件修改",
                    "可疑度分数": 0.95
                }
                注意：若包含文件路径，请将反斜杠双写为 \\\\，或改用正斜杠 /
                """
            else:
                prompt += """
                请执行以下任务：
                1. 分析此进程的时间序列，将进程的行为总结为一句话，注意保留关键内容和关键文件名/套接字等，但是不需要额外的推测。
                2. 根据你的总结，请以安全分析师的角度，分析这个进程的行为是否可能为高级持续性威胁（APT）攻击的一部分。
                给出可疑度分数，评分范围为：0~0.3（正常或低风险）；0.3~0.8（中等风险，需进一步调查）；0.8~1（高风险，需立即处置）

                请注意，以下行为应视为系统正常或低风险流程(可疑度分数<=0.3)：
                [
                    {
                        "名称": "fluxbox 被动事件接收行为",
                        "特征": "SUBJECT_PROCESS 为 'fluxbox'；行为仅包含连续大量 EVENT_RECVFROM 事件；事件通信对象交替为 'NetFlowObject' 和 'unknown'；每对事件共享同一时间戳；频率高、时间间隔短；未包含 WRITE、OPEN、EXECUTE、CONNECT 等主动调用",
                        "理由": "该行为符合图形窗口管理器 fluxbox 在图形会话中被动监听系统事件、输入消息或图形层通知的特征。事件中对象不明确但行为极为稳定，表现为典型的图形环境中的消息轮询或事件广播处理流程。行为不涉及任何系统状态修改或安全敏感操作，判定为低风险（可疑度 ≤ 0.3）"
                    },
                    {
                        "名称": "fluxbox 图形窗口管理器的被动通信行为",
                        "特征": "SUBJECT_PROCESS 为 'fluxbox'；行为为大量 EVENT_RECVFROM 事件；来源对象名称为 NetFlowObject 或 unknown，事件总是成对出现；事件时间戳极为接近（间隔小于几百微秒）；未伴随 OPEN、WRITE、EXECUTE、CONNECT、MODIFY_PROCESS 等高风险操作",
                        "理由": "该行为模式为图形窗口管理器在图形会话中的被动监听行为，接收系统广播事件或底层通信通知。通信对象虽未知但行为高度一致、重复出现、且未观察到主动系统操作，属于低风险监听机制，无需判定为可疑（建议可疑度 ≤ 0.3）"
                    },
                    {
                        "名称": "sshd 合法远程登录与交互行为",
                        "特征": "SUBJECT_PROCESS 为 'sshd: <user> [priv]'；包含交替出现的 READ_SOCKET_PARAMS / WRITE_SOCKET_PARAMS / RECVMSG / CLONE 等事件；通信对象为 NetFlowObject 与 unknown 的成对结构；可能涉及对 /dev/ptmx 的 READ 和 WRITE 操作；过程最后出现子进程 fork（EVENT_CLONE）并建立 tty 会话；无 chmod、exec 非法路径、suid 提权等异常操作",
                        "理由": "该行为是标准 SSH 登录过程中的服务端处理逻辑，包括 socket 参数读取、终端绑定、数据收发以及创建交互式 shell 子进程。日志中无外联异常、无多主机横跳、无非法文件访问，连接 IP 合法（若可验证）、路径规范、无权限操作，符合 OpenSSH 的典型实现，判定为低风险（可疑度 ≤ 0.2）"
                    },
                    {
                        "名称": "sshd 用户终端子会话交互行为",
                        "特征": "SUBJECT_PROCESS 为 'sshd: <user>@pts/<n>'；事件以 OPEN 和 WRITE 交替访问 /dev/null 为主；每对 OPEN/WRITE 操作对象均为 /dev/null，表现为规律性重复写入；事件对象名为 FILE_OBJECT_BLOCK 或 unknown；无权限修改、无执行行为、无文件写入其他路径",
                        "理由": "该行为代表用户登录 SSH 后建立交互式 shell（如 bash、sh），其输出或日志被重定向至 /dev/null，是标准的终端初始化或后台任务控制逻辑。无路径异常、无权限操作、系统调用模式稳定，符合安全终端会话的典型特征，属于低风险行为（可疑度 ≤ 0.2）"
                    },
                    {
                        "名称": "ELF 动态链接库加载与内存映射行为",
                        "特征": "SUBJECT_PROCESS 可为空或为常见前台/后台进程；事件序列包含 OPEN → READ → MMAP → MPROTECT 操作；路径为 /usr/lib/x86_64-linux-gnu/*.so.* 形式的共享库；事件对象多为 MemoryObject 和 FILE_OBJECT_BLOCK；可出现 unknown 标记对象但未配套高风险系统调用；行为高频、序列规则、路径受控",
                        "理由": "该行为是 ELF 可执行文件在加载共享库时的标准行为流程，包括对动态链接库文件的打开、读取、内存映射以及可执行权限设定（mprotect），这些操作广泛出现在几乎所有运行中用户进程中，属于 Linux 的正常加载机制。行为路径规范、调用序列标准、无写入或执行风险，判定为低风险（可疑度 ≤ 0.2）"
                    }
                ]

                只给出json格式的输出，即一个{}内的字符串，不需要添加其他解释，示例输出格式:
                {
                    "行为总结": "进程 X 执行多个未经授权的文件修改",
                    "可疑度分数": 0.95
                }

                """

            print(prompt)
            response = llm_model.query(prompt)

        print(response)
        
        match = re.search(r'{.*}', response, re.DOTALL)
        if match:
            json_str = match.group(0)
            try:
                response = json.loads(json_str)
            except json.JSONDecodeError as e:
                print("JSON 解析错误:", e)
        else:
            print("未找到 JSON 格式的数据")
            return suspicious_processes, temporal_patterns, process_scores 

        if response["可疑度分数"] > 0.3:
            suspicious_processes.append(source)
            temporal_patterns[source] = response["行为总结"]+'\n'
        
        process_scores[source] = response["可疑度分数"]

    return suspicious_processes, temporal_patterns, process_scores


def analyze_community(suspicious_processes, temporal_patterns, community, llm_model):
    if not suspicious_processes:
        return {}
    
    BATCH_SIZE = 50
    final_severity_dict = {}
    
    for batch_start in range(0, len(suspicious_processes), BATCH_SIZE):
        if len(suspicious_processes) == 1:
            return {}

        batch_end = batch_start + BATCH_SIZE
        batch_processes = suspicious_processes[batch_start:batch_end]
        relation = check_community_relation(batch_processes, community)
        log_summary = ""
        process_count = 0
        for index, process in enumerate(batch_processes):
            if process in temporal_patterns:
                behavior_summary = temporal_patterns[process]
                log_summary += f"进程 {index}: {behavior_summary}\n"
                process_count += 1
        
        if not log_summary: 
            continue
            
        prompt = f"""
        你是一位安全分析师，以下是系统日志中编号为 0 到 {len(batch_processes)-1} 的相关进程的行为摘要及其与关键节点的交互记录:
        """
        prompt += log_summary
        prompt += relation
        prompt += "\n"
        if config.theia == 0:
            prompt += """
            请以安全分析师的角度，综合分析这些进程的行为是否可能为高级持续性威胁（APT）攻击的一部分。
            给出可疑度分数，评分范围为：0~0.3（正常或低风险）；0.3~0.8（中等风险，需进一步调查）；0.8~1（高风险，需立即处置）

            请注意，以下行为不应视为高风险流程：
        [
            {
                "名称": "pkg 标准软件包管理行为",
                "可疑度区间": "[0.0, 0.3]",
                "特征": "SUBJECT_PROCESS 为 'pkg'；包含三种标准操作模式：1) OPEN→READ→CLOSE 文件操作（访问/var/db/pkg/*.sqlite、/etc/pkg/*.conf等标准路径，mode≤5）；2) FCNTL 控制命令与SQLite交互（数据量≤4KB/次，含合法journal操作）；3) OPEN→MMAP→CLOSE 配置加载（映射1-8MB标准配置文件）；均使用aue_pread/aue_openat_rwtc等标准IO方法，且无execve/connect/chmod等高危调用",
                "理由": "完整涵盖pkg包管理器的常规操作：数据库维护（含事务处理）、配置加载和文件访问，所有行为均符合FreeBSD/OpenBSD系统设计规范，长期观测中表现出稳定、低风险特性"
            },
            {
                "名称": "pkg 常规元数据写入操作",
                "可疑度区间": "[0.0, 0.3]",
                "特征": "SUBJECT_PROCESS 为 'pkg'；操作类型为连续 WRITE 事件；调用方法为 aue_write；目标文件标识符稳定（BF253D48-3E05-11E8-A5CB-3FA3753A265A）；单次写入量≤35B；写入模式呈现规律性循环（4B→6B→2B→35B）；无文件路径修改或权限变更行为",
                "理由": "该模式符合软件包管理器维护元数据文件的典型特征，表现为小数据量、周期性、固定格式的写入行为，常见于数据库索引更新或状态记录场景，属于低风险系统维护操作"
            },
            {
                "名称": "Postfix 正常本地投递流程",
                "可疑度区间": "[0.0, 0.3]",
                "特征": "SUBJECT_PROCESS 为 'local'；行为包含 setegid/seteuid 权限调整、UNLINK 邮箱锁、发送日志至 /var/run/logpriv；伴随访问 /etc/services、/etc/hosts、/etc/resolv.conf 等配置文件；无异常文件路径，无 execve、chmod、connect 外部地址、权限异常；访问 active/ 邮件队列路径并写入，表现为正常邮件投递处理",
                "理由": "该行为符合 FreeBSD 下 postfix 本地邮件传送代理 'local' 的投递流程，涉及权限调整、日志记录与读取标准配置，无异常访问行为，长期观察中为低风险、常规操作模式"
            },
            {
                "名称": "Cron 启动的 Atrun 执行 at 任务",
                "可疑度区间": "[0.0, 0.3]",
                "特征": "SUBJECT_PROCESS 为 'cron'，后跟 sh 启动 /usr/libexec/atrun；访问 /etc/spwd.db、/etc/login.conf、/etc/group、/etc/pwd.db 等文件；权限变更包括 setgid、setuid、seteuid、umask；切换目录至 /root；通过 /var/run/logpriv unix socket 日志通信；无外部网络连接，无可疑写入或异常执行路径",
                "理由": "行为链完整、顺序规范，符合计划任务通过 atrun 执行的标准流程，未出现超权限访问、未知路径或代码注入等特征，应视为可信行为"
            },
            {
                "名称": "低风险 find 扫描",
                "可疑度区间": "[0.0, 0.3]",
                "特征": "SUBJECT_PROCESS 为 \"find\" 或 \"sh;find\"；系统调用仅包含 open、close、fchdir；文件访问模式 mode ≤ 5；访问路径限制在以下目录或其子目录下：/usr/local/lib、/usr/lib/python*、/usr/local/lib/python*、~/.cache、~/.local、/opt、/tmp、/var/tmp；路径不包含 passwd、shadow、ssh、.key、id_rsa 等敏感关键字；调用序列中无 execve、unlink、chmod、connect、sendto、write 等高风险行为，亦无属性变更",
                "理由": "该行为模式常见于开发工具链、构建系统或脚本对依赖目录的合法遍历操作，未对系统状态造成任何修改，属于典型的正常行为或低异常行为，应排除误报"
            },
            {
                "名称": "低风险 shell 目录遍历",
                "可疑度区间": "[0.0, 0.3]",
                "特征": "SUBJECT_PROCESS 为 \"sh;...\"；事件序列为 open → fchdir → close 循环组合；文件访问模式 mode ≤ 5；访问路径不涉及任何敏感目录关键词；调用序列未出现 write、exec、connect、chmod 等副作用操作",
                "理由": "通常由 shell 脚本或调度任务自动触发，访问行为仅限于目录遍历，未进行任何敏感操作，符合系统正常任务模式"
            },
            {
                "名称": "中等风险源码/密钥路径 find 扫描",
                "可疑度区间": "(0.3, 0.8)",
                "特征": "SUBJECT_PROCESS 为 find；行为为 open → fchdir → close 循环组合，mode ≤ 5；访问路径包含 /crypto/、/ssl/、/root/、.ssh、id_rsa、authorized_keys 等敏感目录关键词；调用序列未包含写入或执行行为",
                "理由": "此类行为未对系统产生直接破坏，但访问意图疑似为信息收集，且路径集中于高价值目标区域，可能为 APT 侦查阶段行为，建议标记为中等风险并关联上下文进一步审查"
            },
            {
                "名称": "alpine 邮件客户端正常行为",
                "可疑度区间": "[0.0, 0.3]",
                "特征": "进程名为 'alpine'，行为包括用户识别、配置加载、终端交互、邮件读取与草稿写入等。调用序列规范，主要包含 aue_read 与 aue_write 操作 /dev/tty，以及对 /home/user/#pico* 草稿文件的 OPEN、WRITE、TRUNCATE、CLOSE 操作。无 execve、connect、chmod 等高危系统调用，路径正常，无越权访问",
                "理由": "该行为为典型的终端邮件客户端使用流程，符合用户主动操作特征，长期观察中稳定，属于低风险行为模式"
            },
            {
                "名称": "Cron 作业调度任务执行",
                "可疑度区间": "[0.0, 0.3]",
                "特征": "由cron启动sh子进程执行固定命令；依次访问 /etc/spwd.db、/etc/login.conf、/etc/group 等配置文件；通过unix socket与 /var/run/logpriv 通信；无异常系统调用，权限变更合理、无外部连接",
                "理由": "符合 FreeBSD 下 cron 计划任务执行的标准初始化与环境加载流程"
            },
            {
                "名称": "Atrun 执行 at 计划任务",
                "可疑度区间": "[0.0, 0.3]",
                "特征": "由 atrun 程序按时唤起，访问 libmap.conf、ld-elf.so.hints 及多种系统库文件（如 libc.so、libpam.so）；加载动态链接库并切换目录至 /var/at/jobs/；行为中无 exec、网络连接、权限异常或异常路径",
                "理由": "符合系统 at 任务调度组件 atrun 的常规运行逻辑"
            },
            {
                "名称": "inetd管理网络连接, 并启动相应的imapd服务进行读写操作",
                "特征": "inetd（网络守护进程）接受了传入的网络连接，并通过 FORK 操作创建子进程来处理这些连接，具体为 imapd 服务，即 imapd 守护进程一系列读写操作, 可视为低风险,
                "理由": "无风险操作"
            }
        ]
            请仅输出一个 JSON 列表，每个元素格式为：
        {"进程序号": int, "可疑度分数": float}
        """
        else:
            prompt += """
            请以安全分析师的角度，综合分析这些进程的行为是否可能为高级持续性威胁（APT）攻击的一部分。
            给出可疑度分数，评分范围为：0~0.3（正常或低风险）；0.3~0.8（中等风险，需进一步调查）；0.8~1（高风险，需立即处置）

            请注意，以下行为应视为系统正常或低风险流程(可疑度分数<=0.3)：
            [
                {
                    "名称": "fluxbox 被动事件接收行为",
                    "特征": "SUBJECT_PROCESS 为 'fluxbox'；行为仅包含连续大量 EVENT_RECVFROM 事件；事件通信对象交替为 'NetFlowObject' 和 'unknown'；每对事件共享同一时间戳；频率高、时间间隔短；未包含 WRITE、OPEN、EXECUTE、CONNECT 等主动调用",
                    "理由": "该行为符合图形窗口管理器 fluxbox 在图形会话中被动监听系统事件、输入消息或图形层通知的特征。事件中对象不明确但行为极为稳定，表现为典型的图形环境中的消息轮询或事件广播处理流程。行为不涉及任何系统状态修改或安全敏感操作，判定为低风险（可疑度 ≤ 0.3）"
                },
                {
                    "名称": "fluxbox 图形窗口管理器的被动通信行为",
                    "特征": "SUBJECT_PROCESS 为 'fluxbox'；行为为大量 EVENT_RECVFROM 事件；来源对象名称为 NetFlowObject 或 unknown，事件总是成对出现；事件时间戳极为接近（间隔小于几百微秒）；未伴随 OPEN、WRITE、EXECUTE、CONNECT、MODIFY_PROCESS 等高风险操作",
                    "理由": "该行为模式为图形窗口管理器在图形会话中的被动监听行为，接收系统广播事件或底层通信通知。通信对象虽未知但行为高度一致、重复出现、且未观察到主动系统操作，属于低风险监听机制，无需判定为可疑（建议可疑度 ≤ 0.3）"
                },
                {
                    "名称": "sshd 合法远程登录与交互行为",
                    "特征": "SUBJECT_PROCESS 为 'sshd: <user> [priv]'；包含交替出现的 READ_SOCKET_PARAMS / WRITE_SOCKET_PARAMS / RECVMSG / CLONE 等事件；通信对象为 NetFlowObject 与 unknown 的成对结构；可能涉及对 /dev/ptmx 的 READ 和 WRITE 操作；过程最后出现子进程 fork（EVENT_CLONE）并建立 tty 会话；无 chmod、exec 非法路径、suid 提权等异常操作",
                    "理由": "该行为是标准 SSH 登录过程中的服务端处理逻辑，包括 socket 参数读取、终端绑定、数据收发以及创建交互式 shell 子进程。日志中无外联异常、无多主机横跳、无非法文件访问，连接 IP 合法（若可验证）、路径规范、无权限操作，符合 OpenSSH 的典型实现，判定为低风险（可疑度 ≤ 0.2）"
                },
                {
                    "名称": "sshd 用户终端子会话交互行为",
                    "特征": "SUBJECT_PROCESS 为 'sshd: <user>@pts/<n>'；事件以 OPEN 和 WRITE 交替访问 /dev/null 为主；每对 OPEN/WRITE 操作对象均为 /dev/null，表现为规律性重复写入；事件对象名为 FILE_OBJECT_BLOCK 或 unknown；无权限修改、无执行行为、无文件写入其他路径",
                    "理由": "该行为代表用户登录 SSH 后建立交互式 shell（如 bash、sh），其输出或日志被重定向至 /dev/null，是标准的终端初始化或后台任务控制逻辑。无路径异常、无权限操作、系统调用模式稳定，符合安全终端会话的典型特征，属于低风险行为（可疑度 ≤ 0.2）"
                },
                {
                    "名称": "ELF 动态链接库加载与内存映射行为",
                    "特征": "SUBJECT_PROCESS 可为空或为常见前台/后台进程；事件序列包含 OPEN → READ → MMAP → MPROTECT 操作；路径为 /usr/lib/x86_64-linux-gnu/*.so.* 形式的共享库；事件对象多为 MemoryObject 和 FILE_OBJECT_BLOCK；可出现 unknown 标记对象但未配套高风险系统调用；行为高频、序列规则、路径受控",
                    "理由": "该行为是 ELF 可执行文件在加载共享库时的标准行为流程，包括对动态链接库文件的打开、读取、内存映射以及可执行权限设定（mprotect），这些操作广泛出现在几乎所有运行中用户进程中，属于 Linux 的正常加载机制。行为路径规范、调用序列标准、无写入或执行风险，判定为低风险（可疑度 ≤ 0.2）"
                }
            ]


            请仅输出一个 JSON 列表，每个元素格式为：
            {"进程序号": int, "可疑度分数": float}
            """


        prompt += """
        示例输出格式(输出一个列表，列表里每个元素均为json格式，不添加其他解释)：
        [
          {
            "进程序号": 0,
            "可疑度分数": 0.9
          },
          {
            "进程序号": 1,
            "可疑度分数": 0.5
          }
        ]
        """
        print(f"正在处理批次 {batch_start//BATCH_SIZE + 1}/{len(suspicious_processes)//BATCH_SIZE + 1}")
        print(prompt)

        response = llm_model.query(prompt)
        print(response)

        match = re.search(r'\[\s*{.*?}\s*]', response, re.DOTALL)
        if match:
            json_list_str = match.group(0)
            response = safe_json_parse(json_list_str)
            if response is None:
                print(f"批次 {batch_start//BATCH_SIZE + 1} 解析失败，跳过")
                continue
        else:
            print("未找到 JSON 列表。")
            continue
        
        batch_severity_dict = {}
        cnt = 0
        for item in response:
            global_index = batch_start + item["进程序号"]
            process_uuid = suspicious_processes[global_index]
            severity = item["可疑度分数"]
            batch_severity_dict[process_uuid] = severity
            cnt += 1
            if cnt == process_count:
                break
        
        print(f"批次 {batch_start//BATCH_SIZE + 1} 分析结果:")
        print(batch_severity_dict)
        
        final_severity_dict.update(batch_severity_dict)
    
    print("所有批次处理完成，最终结果:")
    print(final_severity_dict)
    return final_severity_dict

def generate_llm_report(window_id, malicious_nodes, graph, llm_model, behavior_summaries, path):
    process_actions = {}
    for node in malicious_nodes:
        if node in behavior_summaries:
            process_actions[node] = {
                "path": graph.nodes[node].get('properties_map_exec', 'N/A'),
                "summary": behavior_summaries[node]
            }

    prompt = f"""你是一位安全分析师，根据以下进程行为摘要生成APT攻击链分析：

=== 分析要求 ===
1. 描述可能的APT攻击链（可能是完整攻击链也可能是攻击链的一部分）
2. 请分析其中攻击者使用的TTP技术
3. 相应的ATT&CK技术（注意技术编号映射的准确性）
4. 推断可能的攻击意图
5. 建议的处置措施
6. 分析威胁性最高的2个进程使用的漏洞、ATT&CK 技术、建议的处置措施
7. 用markdown格式输出

=== 示例格式 ===
```markdown
### APT攻击链 - 窗口{window_id}

**攻击链**  
阶段1.xxx:
阶段2.xxx:
....

**TTP技术** 

**ATT&CK技术映射**
T1098: Account Manipulation

**攻击意图**

**处置措施**

### 节点 id (节点名称)

#### 使用的漏洞/技术

#### 具体的 ATT&CK 技术编号

#### 建议的处置措施

```

=== 关键节点行为 ===
{chr(10).join(
    f"节点 {pid} ({info['path']}): {info['summary']}" 
    for pid, info in process_actions.items()
)}
"""

    try:
        base_report = llm_model.query(prompt[:3000])  
        pattern = r'```markdown(.*?)```' 
        report=re.findall(pattern, base_report, re.DOTALL)
        report = "".join(report)
        
        print(prompt)

        report_path = path + f"/window_{window_id}_apt_chain.md"

        with open(report_path, "w", encoding='utf-8') as f:
            f.write(base_report) # fenghuo
        print(f"报告已保存到: {report_path}")
        return report_path

    except Exception as e:
        print(f"报告生成失败（已简化处理）: {str(e)}")
        return None