import base64
import datetime
import hashlib
import ipaddress
import platform
import re
import subprocess
from pathlib import Path

MITM_CA_PEM = Path.home() / '.mitmproxy' / 'mitmproxy-ca-cert.pem'
MITM_CA_BUNDLE = Path.home() / '.mitmproxy' / 'mitmproxy-ca.pem'


def _pem_to_sha1(pem_text: str):
    m = re.search(r'-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----', pem_text, re.DOTALL)
    if not m:
        return None
    der = base64.b64decode(re.sub(r'\s', '', m.group(1)))
    return hashlib.sha1(der).hexdigest().upper()


def _local_ca_sha1():
    if not MITM_CA_PEM.exists():
        return None
    return _pem_to_sha1(MITM_CA_PEM.read_text(encoding='utf-8'))


def is_certificate_installed(cert_name='mitmproxy'):
    # 先读出本机 mitmproxy CA 的 SHA-1 指纹；没有文件说明 mitmproxy 还没初始化，视为未安装
    local_fp = _local_ca_sha1()
    if local_fp is None:
        return False

    if platform.system() == 'Windows':
        # 证书必须在 Trusted Root (ROOT) store 里浏览器 / OS 才真正信任它，
        # 放在 MY (Personal) 或 CA (Intermediate) 里浏览器不会信（这是我们
        # 之前会误判"已安装"但浏览器依然报证书错误的根因）。
        #
        # certutil -addstore root "..." 在有/无管理员权限时落盘位置不同：
        #   - 有管理员：LocalMachine\Root
        #   - 无管理员：CurrentUser\Root
        # 两个位置浏览器都会读，我们也都要查一遍。
        def _root_store_contains(extra_args):
            try:
                result = subprocess.run(
                    ['certutil', *extra_args, '-store', 'root', cert_name],
                    capture_output=True, timeout=5,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return False
            if result.returncode != 0:
                return False
            # "(sha1):" 标签在中英文 Windows 下都一致；冒号兼容全角以防万一。
            # 用 utf-8 + replace 解码：即便 certutil 在中文系统输出 GBK，
            # 哈希行里的字节仍是 ASCII，不受影响。
            text = result.stdout.decode('utf-8', errors='replace')
            for m in re.finditer(r'\(sha1\)\s*[:：]\s*([0-9a-fA-F ]+)', text, re.IGNORECASE):
                fp = m.group(1).replace(' ', '').upper()
                if fp == local_fp:
                    return True
            return False

        # LocalMachine\Root（默认作用域）
        if _root_store_contains([]):
            return True
        # CurrentUser\Root
        if _root_store_contains(['-user']):
            return True
        return False
    elif platform.system() == 'Darwin':
        try:
            # -Z 输出每张证书的 SHA-1/SHA-256，-a 列出全部同名证书
            result = subprocess.run(
                ['security', 'find-certificate', '-a', '-c', cert_name, '-Z'],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                return False
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith('SHA-1 hash:'):
                    fp = line.split(':', 1)[1].strip().upper()
                    if fp == local_fp:
                        return True
            return False
        except FileNotFoundError:
            raise NotImplementedError("此系统中未找到 security 命令")
    else:
        raise NotImplementedError(f"暂不支持该系统: {platform.system()}")


def _cert_not_after_utc(cert):
    try:
        return cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def ensure_wss_cert(cert_path: Path, key_path: Path):
    """确保 wss 叶子证书存在、由本机 mitmproxy CA 签发、且未接近过期。
    必要时用 ~/.mitmproxy/mitmproxy-ca.pem 重新签发。

    复用"用户已信任 mitmproxy CA"这一前提：wss 叶子证书因此在浏览器里自动受信任，
    用户无需额外安装任何证书。

    返回 (cert_path_str, key_path_str)；若 mitmproxy CA 尚未生成则返回 None。
    """
    if not MITM_CA_BUNDLE.exists():
        return None

    # 延迟导入：cryptography 是 mitmproxy 的传递依赖，必然可用，但放在顶层会拖慢启动
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    try:
        ca_bytes = MITM_CA_BUNDLE.read_bytes()
        ca_key = serialization.load_pem_private_key(ca_bytes, password=None)
        ca_cert = x509.load_pem_x509_certificate(ca_bytes)
    except Exception:
        return None

    now = datetime.datetime.now(datetime.timezone.utc)

    # 现有证书若由本机 CA 签发且剩余有效期 > 7 天则直接复用
    if cert_path.exists() and key_path.exists():
        try:
            existing = x509.load_pem_x509_certificate(cert_path.read_bytes())
            if (existing.issuer == ca_cert.subject
                    and _cert_not_after_utc(existing) > now + datetime.timedelta(days=7)):
                return str(cert_path), str(key_path)
        except Exception:
            pass

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'CN'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'wxdown-service'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'wxdown-service'),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName('localhost'),
                x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
                x509.IPAddress(ipaddress.IPv6Address('::1')),
            ]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    return str(cert_path), str(key_path)
