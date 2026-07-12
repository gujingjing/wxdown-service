import mitmproxy.http
import mitmproxy.ctx
import json
from urllib.parse import urlparse, parse_qs, urlencode
import time
from typing import Optional
from bs4 import BeautifulSoup


def cookie_header_to_set_cookie(cookie_header):
    if not cookie_header:
        return None
    parts = []
    for item in cookie_header.split(';'):
        item = item.strip()
        if item and '=' in item:
            parts.append(f"{item}; Path=/")
    return ', '.join(parts) if parts else None


def get_first(query_params, key):
    value = query_params.get(key, [None])[0]
    return value if value else None


def build_profile_ext_url(biz, uin, key, pass_ticket):
    params = {
        "action": "getmsg",
        "__biz": biz,
        "offset": "0",
        "count": "10",
        "uin": uin,
        "key": key,
        "pass_ticket": pass_ticket,
        "f": "json",
        "is_ok": "1",
        "scene": "124",
    }
    return "https://mp.weixin.qq.com/mp/profile_ext?" + urlencode(params)


def extract_set_cookie(flow):
    values = []
    response_cookie = flow.response.headers.get("Set-Cookie")
    request_cookie = cookie_header_to_set_cookie(flow.request.headers.get("Cookie"))
    if response_cookie:
        values.append(response_cookie)
    if request_cookie:
        values.append(request_cookie)
    return ', '.join(values) if values else None


def extract_profile(content):
    name = None
    avatar = None
    if not content:
        return name, avatar

    try:
        soup = BeautifulSoup(content, 'html.parser')
        name_tag = soup.css.select_one('.wx_follow_nickname')
        avatar_tag = soup.css.select_one('.wx_follow_avatar > img.wx_follow_avatar_pic')
        if name_tag:
            name = name_tag.get_text(strip=True)
        if avatar_tag:
            avatar = avatar_tag['src']
    except Exception as e:
        print(f"Error parsing HTML: {e}")
    return name, avatar


class ExtractWxCredentials:
    def __init__(self):
        self.cookies = {}
        self.pending = {}
        self.latest_set_cookie = None

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
                    set_cookie = item.get('set_cookie')
                    if set_cookie and 'wap_sid2=' in set_cookie:
                        self.latest_set_cookie = set_cookie
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"加载已有 credentials.json 失败: {e}")

    def save_credentials(self, biz, url, set_cookie_header, name=None, avatar=None, source_url=None):
        source = source_url or url
        path = urlparse(source).path
        print(f'命中请求: biz={biz}, path={path}')
        existing = self.cookies.get(biz, {})
        self.cookies[biz] = {
            "biz": biz,
            "name": name or existing.get("name"),
            "avatar": avatar or existing.get("avatar"),
            "url": url,
            "set_cookie": set_cookie_header,
            "source_url": source,
            "timestamp": int(time.time() * 1000),
        }
        if mitmproxy.ctx.options.credentials:
            with open(mitmproxy.ctx.options.credentials, "w", encoding="utf-8") as file:
                json.dump(list(self.cookies.values()), file, indent=4, ensure_ascii=False)

    def flush_pending_with_cookie(self, set_cookie_header):
        for biz, item in list(self.pending.items()):
            self.save_credentials(
                biz,
                item["url"],
                set_cookie_header,
                item.get("name"),
                item.get("avatar"),
                item.get("source_url"),
            )
            self.pending.pop(biz, None)

    def response(self, flow: mitmproxy.http.HTTPFlow):
        # 检查请求的 URL 是否符合过滤器
        parsed_url = urlparse(flow.request.url)
        if parsed_url.netloc != 'mp.weixin.qq.com':
            return
        print(parsed_url)

        set_cookie_header = extract_set_cookie(flow)
        if set_cookie_header and 'wap_sid2=' in set_cookie_header:
            self.latest_set_cookie = set_cookie_header
            self.flush_pending_with_cookie(set_cookie_header)
        else:
            set_cookie_header = None

        query_params = parse_qs(parsed_url.query)
        biz = get_first(query_params, '__biz')
        uin = get_first(query_params, 'uin')
        key = get_first(query_params, 'key')
        pass_ticket = get_first(query_params, 'pass_ticket')
        if not biz or not uin or not key or not pass_ticket:
            return

        name, avatar = extract_profile(flow.response.content)
        credential_url = build_profile_ext_url(biz, uin, key, pass_ticket)
        self.pending[biz] = {
            "url": credential_url,
            "source_url": flow.request.url,
            "name": name,
            "avatar": avatar,
        }

        usable_cookie = set_cookie_header or self.latest_set_cookie
        if usable_cookie:
            self.save_credentials(biz, credential_url, usable_cookie, name, avatar, flow.request.url)
            self.pending.pop(biz, None)
        else:
            print(f'暂存请求: biz={biz}, path={parsed_url.path}, 等待 wap_sid2')

addons = [
    ExtractWxCredentials(),
]
