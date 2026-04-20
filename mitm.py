import multiprocessing
import os
import queue
import re
import sys
import threading
import time
from pathlib import Path

from mitmproxy.tools.main import mitmdump

import utils
from logger import logger

SRC_PATH = Path.absolute(Path(__file__)).parent
PLUGIN_FILE = str(SRC_PATH / 'resources' / 'credential.py')
CREDENTIALS_FILE = str(SRC_PATH / 'resources' / 'data' / 'credentials.json')


def mitmproxy_process(args: list[str], output_queue: multiprocessing.Queue):
    sys.stdout = sys.stderr = utils.Capture(output_queue)
    # 清除继承自父进程/用户 shell 的代理环境变量，防止 mitmproxy 把自己当作上游代理导致死循环
    for k in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'):
        os.environ.pop(k, None)
    while True:
        print(f'Run mitmdump process {args} ({os.getpid()})...', flush=True)
        try:
            mitmdump(args)
        except KeyboardInterrupt:
            # mitmdump 通常会吞掉 SIGINT 然后正常 return；这里是为了处理它透传上来的极少数情况
            break
        logger.info(f'mitmdump process terminated')
        time.sleep(3)
        logger.info(f'重启 mitm 进程')


def start(port: str, debug = False):
    # 启动 mitmproxy 并加载 credentials 插件
    args = ['-p', port, '-s', PLUGIN_FILE, '--set', 'credentials='+CREDENTIALS_FILE]
    mitm_output_queue = multiprocessing.Queue()
    mitm_process = multiprocessing.Process(target=mitmproxy_process, args=(args, mitm_output_queue), daemon=True)
    mitm_process.start()

    start_time = time.time()
    proxy_address = None
    error_line = None

    while time.time() - start_time < 10:
        try:
            line = mitm_output_queue.get(timeout=0.1)
            logger.info(line)
            if "HTTP(S) proxy listening at" in line:
                match = re.search(r'\*:(\d+)', line)
                port = match.group(1)
                proxy_address = f"http://127.0.0.1:{port}"
                break
            elif "address already in use" in line.lower():
                error_line = line
                break
        except queue.Empty:
            pass

    threading.Thread(target=log_mitmproxy_output, args=(mitm_output_queue, debug), daemon=True).start()

    return proxy_address, error_line


def log_mitmproxy_output(mitm_output_queue: multiprocessing.Queue, debug):
    while True:
        line = mitm_output_queue.get()

        if debug:
            logger.debug(line)
        else:
            # 忽略 mitmproxy 的日志
            pass
