"""
RSA 双向加解密脚本

使用方法:
    加密: mitmdump -p 9999 -s rsa.py --ssl-insecure field=password key=your_public_key
    解密: mitmdump -p 8888 -s rsa.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password key=your_private_key

参数说明:
    field=password: 需要处理的字段，多个字段用逗号分隔
    key: RSA密钥文件路径(.pem)或Base64格式的密钥
    
注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段处理
    3. 自动检测运行模式（加密/解密）
    4. 加密结果使用 Base64 编码
"""

import sys
import os
from mitmproxy import http
import base64
import logging
import json
from urllib.parse import parse_qs, urlencode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import textwrap

# 配置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_config():
    """获取配置参数"""
    all_args = sys.argv
    fields = []
    key_str = None
    
    for arg in all_args:
        if arg.startswith('field='):
            fields = [field.strip() for field in arg.replace('field=', '').split(',') if field.strip()]
        elif arg.startswith('key='):
            key_path = arg.replace('key=', '').strip()
            if key_path.endswith('.pem'):
                try:
                    with open(key_path, 'r') as f:
                        key_str = f.read().strip()
                except Exception as e:
                    logging.error(f"读取密钥文件失败: {e}")
                    raise
            else:
                key_str = key_path
    
    if not fields:
        fields = ['password']  # 默认字段
        
    if not key_str:
        raise ValueError("未提供RSA密钥")
        
    logging.info(f"需要处理的字段: {fields}")
    return fields, key_str

def is_encrypt_mode():
    """判断是加密还是解密模式"""
    return '--mode' not in ' '.join(sys.argv)

class RsaProcessor:
    def __init__(self, fields, key_str):
        self.fields = fields
        self.is_encrypt = is_encrypt_mode()
        self.cipher = None
        
        try:
            # 检查密钥内容是否已经是PEM格式
            if "-----BEGIN" not in key_str:
                # 如果不是PEM格式，进行转换
                if self.is_encrypt:
                    key_str = ("-----BEGIN PUBLIC KEY-----\n" +
                             "\n".join(textwrap.wrap(key_str.strip(), 64)) +
                             "\n-----END PUBLIC KEY-----")
                else:
                    key_str = ("-----BEGIN PRIVATE KEY-----\n" +
                             "\n".join(textwrap.wrap(key_str.strip(), 64)) +
                             "\n-----END PRIVATE KEY-----")
            
            key = RSA.importKey(key_str)
            self.cipher = PKCS1_v1_5.new(key)
            mode = "加密" if self.is_encrypt else "解密"
            logging.info(f"初始化 RSA {mode}处理器")
            
        except Exception as e:
            logging.error(f"初始化RSA处理器失败: {e}")
            self.cipher = None
    
    def process_value(self, value: str) -> str:
        """处理单个值"""
        try:
            if self.is_encrypt:
                encrypted = self.cipher.encrypt(value.encode('utf-8'))
                return base64.b64encode(encrypted).decode('utf-8')
            else:
                decoded = base64.b64decode(value)
                decrypted = self.cipher.decrypt(decoded, None)
                if decrypted is None:
                    raise ValueError("解密失败")
                return decrypted.decode('utf-8')
        except Exception as e:
            logging.error(f"处理失败: {e}")
            return value

    def process_json_data(self, json_data: dict) -> tuple[dict, bool]:
        """处理JSON数据"""
        modified = False
        for field in self.fields:
            if field in json_data:
                try:
                    if isinstance(json_data[field], (dict, list)):
                        value = json.dumps(json_data[field])
                    else:
                        value = str(json_data[field])
                        
                    mode = "加密" if self.is_encrypt else "解密"
                    logging.info(f"JSON字段 {field} 待{mode}值: {value}")
                    processed_value = self.process_value(value)
                    
                    if not self.is_encrypt:
                        try:
                            # 尝试解析JSON
                            json_data[field] = json.loads(processed_value)
                        except json.JSONDecodeError:
                            # 如果不是JSON，保持原样
                            json_data[field] = processed_value
                    else:
                        json_data[field] = processed_value
                        
                    modified = True
                    logging.info(f"JSON字段 {field} {mode}完成")
                except Exception as e:
                    logging.error(f"处理字段 {field} 失败: {e}")
        return json_data, modified

    def process_form_data(self, form_data: str) -> tuple[str, bool]:
        """处理表单数据"""
        params = parse_qs(form_data, keep_blank_values=True)
        modified = False
        
        for field in self.fields:
            if field in params:
                try:
                    values = params[field]
                    mode = "加密" if self.is_encrypt else "解密"
                    if isinstance(values, list):
                        processed_values = []
                        for value in values:
                            logging.info(f"表单字段 {field} 待{mode}值: {value}")
                            processed_values.append(self.process_value(value))
                        params[field] = processed_values
                    else:
                        logging.info(f"表单字段 {field} 待{mode}值: {values}")
                        params[field] = self.process_value(values)
                    modified = True
                    logging.info(f"表单字段 {field} {mode}完成")
                except Exception as e:
                    logging.error(f"处理字段 {field} 失败: {e}")

        for key in params:
            if isinstance(params[key], list) and len(params[key]) == 1:
                params[key] = params[key][0]

        return urlencode(params), modified

    def request(self, flow: http.HTTPFlow) -> None:
        """处理请求"""
        try:
            content_type = flow.request.headers.get("Content-Type", "")
            mode = "加密" if self.is_encrypt else "解密"
            logging.info("=" * 50)
            logging.info(f"请求URL: {flow.request.pretty_url}")
            logging.info(f"请求方法: {flow.request.method}")
            logging.info(f"Content-Type: {content_type}")
            logging.info(f"运行模式: {mode}")

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
                logging.info(f"{mode}后的请求数据: {flow.request.content.decode('utf-8')}")

            logging.info("=" * 50)

        except Exception as e:
            logging.error(f"处理请求失败: {e}")
            import traceback
            logging.error(traceback.format_exc())

# 获取配置并注册插件
fields, key_str = get_config()
addons = [RsaProcessor(fields, key_str)]