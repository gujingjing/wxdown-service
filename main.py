import argparse
import multiprocessing
import platform
import sys

import mitm
import utils
import watcher
from ui.console import console
from ui.startup import startup_ui_loop


def _fail(title: str, reason: str | None):
    """打印真实失败原因并在 Windows 上等待用户确认，避免 PowerShell/双击启动时窗口闪退。"""
    console.print(f'[bold red]{title}[/]')
    if reason:
        console.print(f'原因: {reason}')
    else:
        console.print('未捕获到具体错误信息，请查看 resources/logs/wxdown.log 或加 -d 重试')
    # Windows 下若 stdin 可读，等用户按回车再退出
    if platform.system() == 'Windows':
        try:
            input('按回车键退出...')
        except Exception:
            pass
    sys.exit(1)


def main():
    # 命令行参数解析
    parser = argparse.ArgumentParser(prog='wxdown-service', description='微信公众号下载助手')
    parser.add_argument('-p', '--port', type=str, default='65000', help='mitmproxy proxy port (default: 65000)')
    parser.add_argument('-w', '--wport', type=str, default='65001', help='websocket port (default: 65001)')
    parser.add_argument('-v', '--version', action='version', version=utils.get_version(), help='display version')
    parser.add_argument('-d', '--debug', action='store_true', help='debug mode')
    args, unparsed = parser.parse_known_args()


    # 启动 mitmproxy 进程
    mitm_proxy_address, mitm_err = mitm.start(args.port, args.debug)
    if mitm_proxy_address is None:
        _fail('启动 mitmproxy 失败', mitm_err)

    # 启动文件监控及 ws 服务进程
    ws_address, watcher_output_queue, watcher_err = watcher.start(args.wport)
    if ws_address is None:
        _fail('启动 watcher 失败', watcher_err)

    # 启动 UI
    startup_ui_loop(watcher_output_queue, mitm_proxy_address, ws_address)


if __name__ == '__main__':
    multiprocessing.freeze_support()

    try:
        main()
    except KeyboardInterrupt:
        print("Ctrl+C pressed, exiting.")
        # 直接 SIGKILL 掉所有 daemon 子进程，跳过 mitmproxy/websockets 的 graceful shutdown
        # 以及 mitm.py 里 mitmdump 重启循环中的 time.sleep(3)，实现立即退出
        for p in multiprocessing.active_children():
            try:
                p.kill()
            except Exception:
                pass
        sys.exit(0)
