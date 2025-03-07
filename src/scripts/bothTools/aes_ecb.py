"""
AES ECB 双向加解密脚本

使用方法:
    加密: mitmdump -p 9999 -s aes_ecb.py --ssl-insecure field=password key=your_key
    解密: mitmdump -p 8888 -s aes_ecb.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password key=your_key

参数说明:
    field: 需要处理的字段，多个字段用逗号分隔
    key: AES密钥（必须为16、24或32字节）

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段处理
    3. 自动检测运行模式（加密/解密）
"""

import sys
import logging
import json
from mitmproxy import http
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from urllib.parse import parse_qs, urlencode

# 配置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_fields_and_key():
    """获取需要处理的字段和密钥"""
    all_args = sys.argv
    fields = []
    key = None
    
    for arg in all_args:
        if arg.startswith('field='):
            fields = [field.strip() for field in arg.replace('field=', '').split(',') if field.strip()]
        elif arg.startswith('key='):
            key = arg.split('=', 1)[1].strip()
    
    if not fields:
        fields = ['password']  # 默认字段
        
    if not key or len(key) not in (16, 24, 32):
        logging.error("请提供有效的 AES 密钥（16、24 或 32 字节）")
        sys.exit(1)
        
    logging.info(f"需要处理的字段: {fields}")
    return fields, key

def is_encrypt_mode():
    """判断是加密还是解密模式"""
    return '--mode' not in ' '.join(sys.argv)

class AESECBProcessor:
    def __init__(self, fields, key):
        self.fields = fields
        self.is_encrypt = is_encrypt_mode()
        self.key = key.encode('utf-8')
        mode = "加密" if self.is_encrypt else "解密"
        logging.info(f"初始化 AES ECB {mode}处理器")

    def process_value(self, value: str) -> str:
        """处理单个值"""
        cipher = AES.new(self.key, AES.MODE_ECB)
        if self.is_encrypt:
            padded_value = pad(value.encode('utf-8'), AES.block_size)
            return base64.b64encode(cipher.encrypt(padded_value)).decode('utf-8')
        else:
            decrypted_value = unpad(cipher.decrypt(base64.b64decode(value)), AES.block_size)
            return decrypted_value.decode('utf-8')

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
fields, key = get_fields_and_key()
addons = [AESECBProcessor(fields, key)] 