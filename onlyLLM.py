import os
import pickle as pkl
import networkx as nx
from data_parser2 import construct_graph, assign_edge_weights_by_event_type, construct_graph2, assign_edge_weights_by_event_type2
from detect_communities import detect_communities
#from cot import analyze_process_patterns, analyze_community, generate_llm_report
from log_utils import *
from llm_wrapper import LLMModel
from llm_api import DashScopeLLMClient
from evaluate_window_detection import evaluate_detection, write_tp_and_fp, get_2hop_neighbors_of_all_nodes
import copy
import json
from report_utils import extract_malicious_subgraph
from django.conf import settings
import token_count


def dynamic_score_adjustment(G, decay_rate=0.3, reinforcement_threshold=0.7):
    """动态调整节点可疑度分数
    Args:
        G: 待处理的图对象
        decay_rate: 衰减系数（每轮分析窗口降低的分数比例）
        reinforcement_threshold: 触发分数强化的最低阈值
    """
    for node in G.nodes:
        if 'suspicion_score' not in G.nodes[node]:
            continue
            
        current_score = G.nodes[node]['suspicion_score']
        
        # 衰减逻辑（适用于所有节点）
        new_score = current_score * (1 - decay_rate)  # 按比例衰减
        
        # 强化逻辑（仅对部分可疑节点生效）
        if (current_score >= reinforcement_threshold and 
            G.nodes[node].get('recent_evidence', False)):
            new_score = min(current_score + 0.1, 1.0)  # 证据强化
            
        G.nodes[node]['suspicion_score'] = max(new_score, 0)  # 确保不低于0

  

# 测试多个窗口的日志文件
def time_correlation(directory, llm_model, input_graph=''):
    entries = os.listdir(directory)
    log_files = []

    for root, dirs, files in os.walk(directory):
        for file in files:
            log_files.append(os.path.join(root, file))

    #print("待处理日志文件序列:", log_files)

    for log_file in log_files:
        print(log_file)
        with open(log_file, 'r', encoding='utf-8') as f:
            log_lines = f.readlines() 

        highest_suspicion = 0.0  # 当前最高可疑度分数
        best_summary = ""  # 对应的最佳总结
        
        # 分段处理日志 fenghuo进程改节点
        for i in range(0, len(log_lines), 25): 
            segment = log_lines[i:i + 25]
            segment_prompt = f"你是一位安全分析师，以下是系统日志中某一个进程的部分事件序列：\n" + "\n".join(segment) 
            # 构建最终的提示词
            segment_prompt += """
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
                "行为总结": " ",
                "可疑度分数": 0.95
            }
            注意：若包含文件路径，请将反斜杠双写为 \\\\，或改用正斜杠 /
            """        
            #print(segment_prompt)
            # 获取当前段落的分析结果
            response = llm_model.query(segment_prompt)
            

            # 提取 JSON 格式的数据
            match = re.search(r'{.*}', response, re.DOTALL)
        
            if match:
                json_str = match.group(0)
                try:
                    response_data = json.loads(json_str)
                    suspicion_score = response_data["可疑度分数"]
                    print(suspicion_score)
                    summary = response_data["行为总结"]
                    print(summary)
                    
                    # 如果当前段的可疑度分数更高，则更新总结和分数
                    if suspicion_score > highest_suspicion:
                        highest_suspicion = suspicion_score
                        best_summary = summary

                except json.JSONDecodeError as e:
                    print("JSON 解析错误:", e)
            else:
                print("未找到 JSON 格式的数据")
                continue  # 跳过当前段

        # 1. 分离文件名和路径 → 获取带后缀的文件名（如"log.txt"）
        file_name_with_ext = os.path.basename(log_file)

        # 2. 分离文件名和后缀 → 获取无后缀的文件名（如"log"）
        file_name = os.path.splitext(file_name_with_ext)[0]
        # 最终返回的最佳总结和可疑度分数
        with open("onlyLLM0.txt", "a", encoding="utf-8") as f:
            # 用\t分隔两个参数，末尾加\n换行（可选）
            f.write(f"{file_name}\t{highest_suspicion}\n")

        '''
        lines = []
        count = 0
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                lines.append(line)
                count += 1
                if count % 100 == 0:
                    print(f"--- 第 {count//100} 段（共100行） ---")
                    print(''.join(lines))
                    lines = []  # 重置临时列表
            # 输出剩余行数
            if lines:
                print(f"--- 最后一段（共 {len(lines)} 行） ---")
                print(''.join(lines))

        '''


    
if __name__ == '__main__':
    # file_path = f"../dataset/split/split15m_83.txt"
    llm_model = LLMModel()
    token_count.reset()

    #theia    
    time_correlation(directory="../dataset/split_by_uuid83", llm_model=llm_model)

    print("Prompt tokens:", token_count.get_prompt())
    print("Output tokens:", token_count.get_output())
    print("Total tokens:", token_count.get_total())
    '''
    # test_single_window(file_path, llm_model, 83)
    llm_model = LLMModel()
    time_correlation(directory="../dataset", llm_model=llm_model)
    '''
