"""
AES-ECB 加密脚本

使用方法:
    mitmdump -p 8888 -s aes_ecb.py --ssl-insecure field=password key=1234567890123456
    mitmdump -p 8888 -s aes_ecb.py --ssl-insecure field=password,username key=1234567890123456

参数说明:
    -p 8888: 监听端口
    -s aes_ecb.py: 指定脚本文件
    --ssl-insecure: 忽略 SSL 证书验证
    field=password: 单个加密字段
    field=password,username: 多个加密字段，用逗号分隔
    key=1234567890123456: AES密钥，必须是16/24/32字节

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段加密
    3. AES密钥必须是16/24/32字节长度
    4. 加密结果使用 Base64 编码
"""

import sys
import os
from mitmproxy import http
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import logging
import json
from urllib.parse import parse_qs, urlencode

# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_encryption_fields():
    """
    从命令行参数获取加密配置
    
    Returns:
        tuple: (加密字段列表, 密钥)
    """
    all_args = sys.argv
    encryption_fields = []
    key = None

    # 遍历所有参数
    for arg in all_args:
        if arg.startswith('field='):
            fields = arg.replace('field=', '')
            encryption_fields = [field.strip() for field in fields.split(',') if field.strip()]
        elif arg.startswith('key='):
            key = arg.replace('key=', '')


    logging.info(f"需要加密的字段: {encryption_fields}")
    return encryption_fields, key

# 获取加密配置
encryption_fields, key = get_encryption_fields()

class AesEcbEncryptInterceptor:
    """AES-ECB 加密拦截器"""
    
    def __init__(self, encryption_fields, key):
        """
        初始化加密器
        
        Args:
            encryption_fields (list): 需要加密的字段名称列表
            key (str): AES密钥，16/24/32字节
        """
        self.encryption_fields = encryption_fields
        self.key = key.encode('utf-8')
        logging.info("成功初始化AES-ECB加密器")

    def encrypt_value(self, plain_text: str) -> str:
        """
        加密单个值
        
        Args:
            plain_text (str): 待加密的文本
            
        Returns:
            str: Base64编码的加密结果
        """
        try:
            cipher = AES.new(self.key, AES.MODE_ECB)
            padded_data = pad(plain_text.encode('utf-8'), AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            return base64.b64encode(encrypted_data).decode('utf-8')
        except Exception as e:
            logging.error(f"加密失败: {e}")
            return plain_text

    def process_json_data(self, json_data: dict) -> tuple[dict, bool]:
        """处理JSON数据"""
        modified = False
        for field in self.encryption_fields:
            if field in json_data:
                try:
                    # 将字段值转换为标准 JSON 字符串（使用双引号）
                    if isinstance(json_data[field], (dict, list)):
                        plain_text = json.dumps(json_data[field], ensure_ascii=False)
                    else:
                        plain_text = str(json_data[field])
                    
                    logging.info(f"JSON字段 {field} 待加密值: {plain_text}")
                    json_data[field] = self.encrypt_value(plain_text)
                    modified = True
                    logging.info(f"JSON字段 {field} 加密完成")
                except Exception as e:
                    logging.error(f"加密字段 {field} 失败: {e}")
        return json_data, modified

    def process_form_data(self, form_data: str) -> tuple[str, bool]:
        """处理表单数据"""
        params = parse_qs(form_data, keep_blank_values=True)
        modified = False

        for field in self.encryption_fields:
            if field in params:
                try:
                    values = params[field]
                    if isinstance(values, list):
                        encrypted_values = []
                        for value in values:
                            logging.info(f"表单字段 {field} 待加密值: {value}")
                            encrypted_values.append(self.encrypt_value(value))
                        params[field] = encrypted_values
                    else:
                        logging.info(f"表单字段 {field} 待加密值: {values}")
                        params[field] = self.encrypt_value(values)
                    modified = True
                    logging.info(f"表单字段 {field} 加密完成")
                except Exception as e:
                    logging.error(f"加密字段 {field} 失败: {e}")

        for key in params:
            if isinstance(params[key], list) and len(params[key]) == 1:
                params[key] = params[key][0]

        return urlencode(params), modified

    def request(self, flow: http.HTTPFlow) -> None:
        """
        处理请求
        
        Args:
            flow: mitmproxy的请求流对象
        """
        try:
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
                    new_content = json.dumps(json_data, separators=(',', ':'))
                    flow.request.content = new_content.encode('utf-8')

            elif "application/x-www-form-urlencoded" in content_type:
                form_data = flow.request.content.decode('utf-8')
                new_content, modified = self.process_form_data(form_data)
                if modified:
                    flow.request.content = new_content.encode('utf-8')

            if modified:
                flow.request.headers["Content-Length"] = str(len(flow.request.content))
                logging.info(f"加密后的请求数据: {flow.request.content.decode('utf-8')}")

            logging.info("=" * 50)

        except Exception as e:
            logging.error(f"处理请求失败: {e}")
            import traceback
            logging.error(traceback.format_exc())

# 注册插件
addons = [AesEcbEncryptInterceptor(encryption_fields, key)] 