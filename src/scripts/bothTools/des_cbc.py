"""
DES CBC 双向加解密脚本

使用方法:
    加密: mitmdump -p 9999 -s des_cbc.py --ssl-insecure field=password key=your_key iv=your_iv
    解密: mitmdump -p 8888 -s des_cbc.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password key=your_key iv=your_iv
"""
import base64
import sys
from mitmproxy import http
import logging
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import json
from urllib.parse import parse_qs, urlencode

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

def get_key_iv():
    """获取密钥和IV"""
    all_args = sys.argv
    key = None
    iv = None
    for arg in all_args:
        if arg.startswith('key='):
            key = arg.replace('key=', '').strip().encode('utf-8')
        elif arg.startswith('iv='):
            iv = arg.replace('iv=', '').strip().encode('utf-8')
    return key, iv

def is_encrypt_mode():
    """判断是加密还是解密模式"""
    return '--mode' not in ' '.join(sys.argv)

class DESCBCProcessor:
    def __init__(self, fields):
        self.fields = fields
        self.is_encrypt = is_encrypt_mode()
        logging.info(f"初始化 DES CBC {'加密' if self.is_encrypt else '解密'}处理器")

    def process_value(self, value: str) -> str:
        """处理单个值"""
        key, iv = get_key_iv()
        cipher = DES.new(key, DES.MODE_CBC, iv)
        if self.is_encrypt:
            return base64.b64encode(cipher.encrypt(pad(value.encode('utf-8'), DES.block_size))).decode('utf-8')
        else:
            return unpad(cipher.decrypt(base64.b64decode(value)), DES.block_size).decode('utf-8')

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
        # 处理请求逻辑...
        pass

# 获取配置并注册插件
fields = get_fields()
addons = [DESCBCProcessor(fields)] 