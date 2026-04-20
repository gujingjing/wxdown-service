# wxdown-service
![](snapshot.png)


## 使用

在控制台执行 `./wxdown-service` 或者双击对应的可执行文件即可，根据控制台的提示进行操作，直至最终出现【🚀 服务启动/监听成功！】。

接下来，将控制台里显示的 websocket 地址（形如 `wss://127.0.0.1:65001`）配置到网站中。

> **前端可以是 https 站点，也可以是本地 http://localhost 的开发环境**：本服务启用了 wss（WebSocket Secure），浏览器允许从任意页面连接 wss（混合内容只拦截"从安全页降级到不安全资源"，wss 属于升级，一律放行）。wss 的 TLS 证书由本机 mitmproxy CA 自动签发，只要按下面指引安装了 mitmproxy CA，**Chrome / Edge / Safari** 会自动信任，无需额外操作。
>
> **Firefox** 使用独立的 CA 信任库，不共享系统钥匙串/证书存储。需要另外在 `about:preferences#privacy` 的"证书 → 查看证书 → 证书颁发机构 → 导入"里手动导入 `~/.mitmproxy/mitmproxy-ca-cert.pem` 并勾选"信任由此证书颁发机构来标识网站"。

> 如果出现证书问题，请按下面的命令安装证书。**程序界面里显示的命令更稳**——它已把路径展开为绝对路径，cmd / PowerShell / Windows Terminal / bash / zsh 下均可直接粘贴执行。下面的命令供参考：
> 
> 注意: 以下命令都是一条指令，有的太长可能换行
> 
> Windows（cmd）：  
> `certutil -addstore root "%userprofile%\.mitmproxy\mitmproxy-ca-cert.cer"`
> 
> Windows（PowerShell）：  
> `certutil -addstore root "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.cer"`
> 
> macOS：  
> `sudo security add-trusted-cert -d -p ssl -p basic -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem`

## 选项

### 指定 mitmproxy 服务端口

通过`-p`选项可以指定代理服务器的端口，如下所示：

`./wxdown-service -p 65000`

### 指定 websocket 服务端口

通过`-w`选项可以指定websocket服务端口，如下所示：

`./wxdown-service -w 65001`

### 调试模式运行

通过`-d`选项可以开启调试模式，会打印更多日志信息：

`./wxdown-service -d`

### 查看版本号

`./wxdown-service -v`


## 源码运行

适合开发调试或验证修改，无需经过 PyInstaller 打包。

### 1. 下载源码
```shell
git clone git@github.com:wechat-article/wxdown-service.git
cd wxdown-service
```

### 2. 创建虚拟环境 & 安装依赖

> 推荐使用 python 3.12

```shell
python3 -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1

pip3 install -r requirements.txt
```

### 3. 启动

```shell
python3 main.py                    # 默认端口 (mitmproxy 65000 / websocket 65001)
python3 main.py -p 65005 -w 65006  # 指定端口
python3 main.py -d                 # 调试模式，打印 mitmproxy 详细日志
```

按 `Ctrl+C` 退出；日志写在 `resources/logs/wxdown.log`。

---

## 自定义构建

由于 macOS 系统要求必须签名才能分发应用程序，所以从 [Releases](https://github.com/wechat-article/wxdown-service/releases) 下载的 macOS 版本不一定能用，这种情况下
推荐从源码自己进行构建。构建步骤如下：

> 如果有大佬知道其他能够解决签名问题的话，不惜赐教。

### 1. 下载源码
```shell
git clone git@github.com:wechat-article/wxdown-service.git
cd wxdown-service
```

### 2. 配置环境 & 安装依赖

> 推荐使用 python 3.12 进行构建

```shell
# 创建虚拟环境
python3 -m venv .
source bin/activate

pip3 install -r requirements.txt
pip3 install pyinstaller
```

> 说明：wss 叶子证书签发依赖 `cryptography`，它是 mitmproxy 的传递依赖，不需要额外声明。

### 3. 打包
```shell
pyinstaller -y --clean wxdown-service.spec
```

### 4. 运行
```shell
cd dist/wxdown-service
./wxdown-service
```

## 常见问题

启动失败时，控制台会直接显示**具体失败原因**（端口占用 / 证书未安装 / wss 证书无法生成 / 代理链路异常 等），请先按提示对症处理。下列为常见场景：

### 1. 提示端口已被占用

mitmproxy 默认使用 65000、WebSocket 默认使用 65001。如被占用，通过 `-p` / `-w` 指定其他端口：

```shell
./wxdown-service -p 65005 -w 65006
```

### 2. 提示未检测到 mitmproxy 证书

按界面给出的命令安装证书即可。证书检测现在按 **SHA-1 指纹**比对，确保系统里装的是当前 `~/.mitmproxy/mitmproxy-ca-cert.pem` 而不是旧的残留。macOS 如果界面仍提示未安装，请打开"钥匙串访问"将该证书的信任策略手动改为"始终信任"。

### 3. 提示 HTTPS 证书校验失败 / 通过代理访问 HTTPS 失败

可能原因：

- 系统代理 HTTP 与 HTTPS 未全部指向 mitmproxy 监听地址
- shell 中已有 `HTTP_PROXY` / `HTTPS_PROXY` 等环境变量指向本服务，引发 mitmproxy 把自己当上游产生死循环（启动前执行 `unset HTTP_PROXY HTTPS_PROXY ALL_PROXY`）
- 系统中存在**旧的** mitmproxy 证书（指纹与当前 `~/.mitmproxy/mitmproxy-ca-cert.pem` 不一致）——先在钥匙串/证书管理器中删除，再重新安装
- 防火墙 / 杀软 拦截 mitmproxy 出站连接

### 4. 前端连 wss 失败

- 前端无论是 https 线上站点还是本地 http://localhost 都可以连 wss（浏览器只拦"从 https 降级到 ws"的组合）
- 确认 mitmproxy CA 已安装并受信任——wss 叶子证书由同一 CA 签发，CA 受信后浏览器自动信任 wss
- **Firefox** 必须单独导入 mitmproxy CA 到其内置信任库（见"使用"一节的说明），否则报 `SEC_ERROR_UNKNOWN_ISSUER`
- 非 Chromium 内核的定制浏览器可能需要重启以刷新证书存储

### 5. 其他问题：查看日志

日志文件位置：

- 打包运行：`<程序目录>/_internal/resources/logs/wxdown.log`
- 源码运行：`resources/logs/wxdown.log`

加 `-d` 运行可输出更详细的 mitmproxy 日志：

```shell
./wxdown-service -d
```


## 功能说明

命令行服务，拦截微信流量并通过 WebSocket 向前端网站实时推送抓取到的凭证。核心流程：

1. 启动 mitmproxy 子进程，加载 `resources/credential.py` 插件，拦截微信文章页面的 Set-Cookie 并写入 `credentials.json`；mitmproxy 同进程重启时会自动从文件把历史凭证读回内存，避免被覆盖清空
2. 启动 watcher 子进程：监听 `credentials.json` 变化，用本机 mitmproxy CA 自动签发带有 `localhost / 127.0.0.1 / ::1` SAN 的 wss 叶子证书（首次生成、过期或 CA 不匹配时会自动续签），启动 wss 服务向前端实时推送，推送时过滤 30 分钟外已失效的数据
3. 检查 mitmproxy CA 是否被系统信任：按 **SHA-1 指纹**比对本地 CA 与钥匙串/证书存储中的同名证书，仅真正匹配才算已安装
4. 用**真实的 HTTPS 请求**探测完整链路（系统代理指向正确 + mitmproxy 能 MITM + 上游可达），失败时给出具体原因（SSL 错误 / 上游不可达 / 超时）
5. 全部就绪时面板显示 🚀，此时可将 wss 地址填入前端网站


## 打包命令(pyinstaller)

```shell
pyinstaller -y --clean -D -c -n wxdown-service --add-data=resources/credential.py:resources --hiddenimport bs4 main.py
```

### 参数说明

- `-D` 打包为一个目录
- `-c` 打开控制台窗口用来输入/输出
- `-add-data` 添加资源文件
- `--hiddenimport` 包含额外依赖

## todo

- [ ] 自动设置系统代理
- [ ] 自动安装 mitmproxy CA 证书（wss 叶子证书已实现自动签发/续签/复用）
