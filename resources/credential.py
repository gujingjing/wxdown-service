import mitmproxy.http
import mitmproxy.ctx
import json
from urllib.parse import urlparse, parse_qs
import time
from typing import Optional
from bs4 import BeautifulSoup


class ExtractWxCredentials:
    def __init__(self):
        self.cookies = {}

    def load(self, loader):
        loader.add_option(
            name="credentials",
            typespec=Optional[str],
            default=None,
            help="指定 Credentials.json 文件路径",
        )

    def running(self):
        # mitmproxy 在同进程内重启（mitm.py 的 while True）时，本类会重新实例化，
        # self.cookies 为空；此时第一次写入会用空字典覆盖磁盘上累计的历史凭证。
        # 在服务就绪后把已有文件读回内存，避免数据丢失。
        path = mitmproxy.ctx.options.credentials
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            if not content:
                return
            for item in json.loads(content):
                biz = item.get('biz')
                if biz:
                    self.cookies[biz] = item
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"加载已有 credentials.json 失败: {e}")

    def response(self, flow: mitmproxy.http.HTTPFlow):
        # 检查请求的 URL 是否符合过滤器
        parsed_url = urlparse(flow.request.url)
        print(parsed_url)
        if parsed_url.path == '/s' and parsed_url.query.startswith("__biz="):
            # 提取 __biz 参数
            print(f'命中请求')
            query_params = parse_qs(parsed_url.query)
            biz = query_params.get('__biz', [None])[0]
            if biz:
                # 提取响应头中的 Set-Cookie 数据
                set_cookie_header = flow.response.headers.get("Set-Cookie")

                # 提取 HTML 中的信息
                name = None
                avatar = None
                if flow.response.content:
                    try:
                        soup = BeautifulSoup(flow.response.content, 'html.parser')
                        name_tag = soup.css.select_one('.wx_follow_nickname')
                        avatar_tag = soup.css.select_one('.wx_follow_avatar > img.wx_follow_avatar_pic')
                        if name_tag:
                            name = name_tag.get_text(strip=True)
                        if avatar_tag:
                            avatar = avatar_tag['src']
                    except Exception as e:
                        print(f"Error parsing HTML: {e}")

                if set_cookie_header:
                    self.cookies[biz] = {
                        "biz": biz,
                        "name": name,
                        "avatar": avatar,
                        "url": flow.request.url,
                        "set_cookie": set_cookie_header,
                        "timestamp": int(time.time() * 1000),
                    }
                    # 将 cookies 数据保存到文件中
                    if mitmproxy.ctx.options.credentials:
                        with open(mitmproxy.ctx.options.credentials, "w", encoding="utf-8") as file:
                            json.dump(list(self.cookies.values()), file, indent=4, ensure_ascii=False)

addons = [
    ExtractWxCredentials(),
]
