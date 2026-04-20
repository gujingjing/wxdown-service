import io
import multiprocessing
import ssl
import urllib.error
import urllib.request
from pathlib import Path

import version as __version
from logger import logger

MITM_CA_PEM = Path.home() / '.mitmproxy' / 'mitmproxy-ca-cert.pem'

SRC_PATH = Path.absolute(Path(__file__)).parent
LOGO_FILE = str(SRC_PATH / 'resources' / 'logo.txt')


# 检查系统代理是否设置正确
def check_system_proxy(mitm_proxy_address):
    proxy_obj = urllib.request.getproxies()
    details = f'将系统代理设置为 [bold green]{mitm_proxy_address.removeprefix('http://')}[/]\n当前系统代理为:\n{proxy_obj}'

    # 注意：Windows 下 urllib.request.getproxies() 可能返回 {'no': '...'}（ProxyOverride 例外列表）
    # 等非 http/https 的 key；所以只能正向判断，不能用 "<"（真子集）判断。
    if 'http' not in proxy_obj or 'https' not in proxy_obj:
        return False, '检测到系统的网络代理设置不正确（http/https 都需要设置）', details
    if proxy_obj['http'] != mitm_proxy_address or proxy_obj['https'] != mitm_proxy_address:
        return False, '检测到系统的网络代理未指向 mitmproxy', details

    # 做一次真实的 HTTPS 探测：
    #   - 走通 ⇒ 代理链路通、mitmproxy 能 MITM、上游出网正常
    #   - SSL 错误 ⇒ 本机 mitmproxy CA 未被信任 或 证书文件与实际拦截不一致
    #   - 超时/其他 ⇒ 上游不可达（防火墙/杀软/上游代理死循环等）
    # 用 mitmproxy 自己的 CA 做 trust anchor，这样 PyInstaller 打包后不依赖系统证书库。
    ctx = ssl.create_default_context()
    if MITM_CA_PEM.exists():
        try:
            ctx.load_verify_locations(cafile=str(MITM_CA_PEM))
        except Exception as e:
            logger.warning(f'加载 mitmproxy CA 失败: {e}')

    probe_url = 'https://mp.weixin.qq.com/favicon.ico'
    try:
        with urllib.request.urlopen(probe_url, timeout=10, context=ctx) as response:
            response.read(1)
        return True, '成功', proxy_obj
    except urllib.error.URLError as e:
        reason = str(getattr(e, 'reason', e))
        logger.error(f'HTTPS 探测失败: {reason}')
        up = reason.upper()
        if 'CERTIFICATE' in up or 'SSL' in up or 'CERT' in up:
            return False, 'HTTPS 证书校验失败', (
                '本机 mitmproxy CA 与实际拦截到的证书不一致，可能是系统内存在旧的 mitmproxy 证书。\n'
                '请删除旧证书后重新安装 ~/.mitmproxy/mitmproxy-ca-cert.pem，并设为"始终信任"。\n'
                f'原始错误: {reason}'
            )
        return False, '通过代理访问 HTTPS 失败', (
            '可能原因：mitmproxy 无法出网（防火墙/杀软拦截），'
            '或启动前 shell 中已存在 HTTP(S)_PROXY 环境变量导致 mitmproxy 把自己当作上游代理产生死循环。\n'
            f'原始错误: {reason}'
        )
    except TimeoutError:
        return False, '通过代理访问 HTTPS 超时', '请检查网络或防火墙设置，5 秒后会自动重试'
    except Exception as e:
        logger.error(f'HTTPS 探测异常: {e}')
        return False, '通过代理访问 HTTPS 异常', f'{e}\n请将日志文件发送给开发者'


def get_version():
    return f"wxdown-service {__version.version}"

class Capture(io.TextIOBase):
    def __init__(self, q: multiprocessing.Queue):
        self.queue = q
        self.buffer = ""

    def writable(self):
        return True

    def write(self, s):
        self.buffer += s
        while '\n' in self.buffer:
            line, _, self.buffer = self.buffer.partition('\n')
            self.queue.put(line)
