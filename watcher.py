import json
import multiprocessing
import queue
import re
import ssl
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

import websockets
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from websockets.sync.server import serve, ServerConnection

import cert
import utils
from logger import logger

# Credentials.json 文件位置
SRC_PATH = Path.absolute(Path(__file__)).parent
CREDENTIALS_DIR = SRC_PATH / 'resources' / 'data'
CREDENTIALS_JSON_PATH = CREDENTIALS_DIR / 'credentials.json'
CREDENTIALS_JSON_FILE = str(CREDENTIALS_JSON_PATH)
WSS_CERT_PATH = CREDENTIALS_DIR / 'wss-cert.pem'
WSS_KEY_PATH = CREDENTIALS_DIR / 'wss-key.pem'


# 保存所有连接的 websocket 客户端；所有访问都要拿 ws_clients_lock
ws_clients: set[ServerConnection] = set()
ws_clients_lock = threading.Lock()
# 串行化 notify_clients，避免 notify_daemon 与 watchdog 事件并发推送
notify_lock = threading.Lock()

# 处理 websocket 连接
def connect_handler(client: ServerConnection):
    with ws_clients_lock:
        ws_clients.add(client)
        size = len(ws_clients)
    logger.debug(f"当前连接客户端数: {size}")
    try:
        for message in client:
            client.send(message)
    except Exception as e:
        logger.debug(f"ws client exited: {e}")
    finally:
        with ws_clients_lock:
            ws_clients.discard(client)
            size = len(ws_clients)
        logger.debug(f"当前连接客户端数: {size}")


# 每5s通知一次
def notify_daemon():
    while True:
        time.sleep(5)
        notify_clients()
        with ws_clients_lock:
            size = len(ws_clients)
        print(f'clients:{size}')


# 通知所有客户端最新的 Credentials 数据
def notify_clients():
    with notify_lock:
        try:
            with open(CREDENTIALS_JSON_FILE, 'r', encoding="utf-8") as file:
                data = file.read()
        except Exception as e:
            logger.error(f"Error reading file: {e}")
            return

        if len(data) == 0:
            return

        try:
            json_data = json.loads(data)
        except json.JSONDecodeError as e:
            # 写入侧非原子时可能读到半截 JSON；下一次文件变更会再触发，吞掉即可
            logger.debug(f"credentials.json 解析失败（可能正被写入）: {e}")
            return

        ts = int((datetime.now() - timedelta(minutes=30)).timestamp() * 1000)
        valid_data = [x for x in json_data if x['timestamp'] > ts]
        result = json.dumps(valid_data, indent=4)
        print(f'credentials:{len(valid_data)}')

        # 先复制快照再迭代；send 失败的客户端集中收集后再统一移除
        with ws_clients_lock:
            snapshot = list(ws_clients)
        dead = []
        for ws_client in snapshot:
            try:
                ws_client.send(result)
            except Exception:
                dead.append(ws_client)
        if dead:
            with ws_clients_lock:
                for c in dead:
                    ws_clients.discard(c)


class CredentialsFileHandler(FileSystemEventHandler):
    def __init__(self, filename):
        self.filename = filename
        logger.debug(f"开始监控文件: {filename}")

    def on_modified(self, event):
        logger.debug(f"on_modified: {event}")
        if event.src_path == self.filename:
            notify_clients()


def watcher_process(port: str, output_queue: multiprocessing.Queue):
    sys.stdout = sys.stderr = utils.Capture(output_queue)

    Path(CREDENTIALS_JSON_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(CREDENTIALS_JSON_FILE).touch()


    event_handler = CredentialsFileHandler(CREDENTIALS_JSON_FILE)
    observer = Observer()
    observer.schedule(event_handler, str(CREDENTIALS_DIR), recursive=True)

    # 用本机 mitmproxy CA 签发 wss 叶子证书；前端是 https 必须走 wss
    wss_paths = cert.ensure_wss_cert(WSS_CERT_PATH, WSS_KEY_PATH)
    if wss_paths is None:
        # mitmproxy CA 还没生成；用户稍后看到"未检测到证书"提示后装证书时 mitmproxy 才会创建 CA
        print("wss 证书启动失败: 未找到 ~/.mitmproxy/mitmproxy-ca.pem")
        logger.error("wss 证书无法生成：~/.mitmproxy/mitmproxy-ca.pem 不存在")
        return
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(certfile=wss_paths[0], keyfile=wss_paths[1])

    try:
        observer.start()

        # 启动 websocket 服务
        logger.info(f"开始启动 websocket 服务")
        threading.Thread(target=notify_daemon, daemon=True).start()

        with serve(connect_handler, "localhost", int(port), ssl=ssl_ctx) as server:
            port = server.socket.getsockname()[1]
            print(f"服务启动成功:{port}")
            logger.info(f"websocket 端口: {port}")
            logger.info(f"websocket 服务启动完毕")
            server.serve_forever()
    except OSError as e:
        # 端口占用等系统错误：务必写到 stdout，父进程才能从 queue 拿到并快速报错
        print(f"watcher启动失败: {e}")
        logger.error(f"watcher启动失败: {e}")
    except Exception as e:
        print(f"watcher启动失败: {e}")
        logger.error(f"watcher启动失败: {e}")
    finally:
        observer.stop()
        observer.join()
        logger.info(f"watcher process terminated")


def start(port: str):
    watcher_output_queue = multiprocessing.Queue()
    process = multiprocessing.Process(target=watcher_process, args=(port, watcher_output_queue,), daemon=True)
    process.start()

    start_time = time.time()
    ws_address = None

    while time.time() - start_time < 10:
        try:
            line = watcher_output_queue.get(timeout=0.1)
            if "服务启动成功" in line:
                match = re.search(r':(\d+)', line)
                port = match.group(1)
                ws_address = f"wss://127.0.0.1:{port}"
                break
            elif "address already in use" in line.lower() or "watcher启动失败" in line:
                break
        except queue.Empty:
            pass

    return ws_address, watcher_output_queue
