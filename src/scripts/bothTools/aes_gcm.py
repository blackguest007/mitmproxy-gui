"""
AES GCM 双向加解密脚本

使用方法:
    加密: mitmdump -p 9999 -s aes_gcm.py --ssl-insecure field=password key=your_key
    解密: mitmdump -p 8888 -s aes_gcm.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password key=your_key

参数说明:
    field: 需要处理的字段，多个字段用逗号分隔
    key: AES密钥（必须为16、24或32字节）

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段处理
    3. 自动检测运行模式（加密/解密）
"""

import sys
from mitmproxy import http
import logging
from Crypto.Cipher import AES
from Crypto.Util import Counter
import base64
import json
from urllib.parse import parse_qs, urlencode

# 配置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_fields():
    """获取需要处理的字段"""
    all_args = sys.argv
    fields = []
    for arg in all_args:
        if arg.startswith('field='):
            fields = [field.strip() for field in arg.replace('field=', '').split(',') if field.strip()]
            break
    return fields or ['password']

def get_key():
    """获取密钥"""
    all_args = sys.argv
    key = None
    for arg in all_args:
        if arg.startswith('key='):
            key = arg.split('=', 1)[1].strip()
    if not key or len(key) not in (16, 24, 32):
        logging.error("请提供有效的 AES 密钥（16、24 或 32 字节）")
        sys.exit(1)
    return key.encode('utf-8')

def is_encrypt_mode():
    """判断是加密还是解密模式"""
    return '--mode' not in ' '.join(sys.argv)

class AesGCMProcessor:
    def __init__(self, fields, key):
        self.fields = fields
        self.is_encrypt = is_encrypt_mode()
        self.key = key
        mode = "加密" if self.is_encrypt else "解密"
        logging.info(f"初始化 AES GCM {mode}处理器")

    def process_value(self, value: str) -> str:
        """处理单个值"""
        cipher = AES.new(self.key, AES.MODE_GCM)
        if self.is_encrypt:
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(value.encode('utf-8'))
            return base64.b64encode(nonce + tag + ciphertext).decode('utf-8')
        else:
            data = base64.b64decode(value)
            nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

    def process_json_data(self, json_data: dict) -> tuple[dict, bool]:
        """处理JSON数据"""
        modified = False
        for field in self.fields:
            if field in json_data:
                json_data[field] = self.process_value(json_data[field])
                modified = True
        return json_data, modified

    def process_form_data(self, form_data: str) -> tuple[str, bool]:
        """处理表单数据"""
        params = parse_qs(form_data, keep_blank_values=True)
        modified = False
        for field in self.fields:
            if field in params:
                params[field] = [self.process_value(value) for value in params[field]]
                modified = True
        return urlencode(params), modified

    def request(self, flow: http.HTTPFlow) -> None:
        """处理请求"""
        content_type = flow.request.headers.get("Content-Type", "")
        logging.info("=" * 50)
        logging.info(f"请求URL: {flow.request.pretty_url}")
        logging.info(f"请求方法: {flow.request.method}")
        logging.info(f"Content-Type: {content_type}")

        modified = False
        if "application/json" in content_type:
            json_data = json.loads(flow.request.content)
            json_data, modified = self.process_json_data(json_data)
            if modified:
                flow.request.content = json.dumps(json_data).encode('utf-8')

        elif "application/x-www-form-urlencoded" in content_type:
            form_data = flow.request.content.decode('utf-8')
            new_content, modified = self.process_form_data(form_data)
            if modified:
                flow.request.content = new_content.encode('utf-8')

        if modified:
            flow.request.headers["Content-Length"] = str(len(flow.request.content))
            logging.info(f"处理后的请求数据: {flow.request.content.decode('utf-8')}")

        logging.info("=" * 50)

# 获取配置并注册插件
fields = get_fields()
key = get_key()
addons = [AesGCMProcessor(fields, key)] 