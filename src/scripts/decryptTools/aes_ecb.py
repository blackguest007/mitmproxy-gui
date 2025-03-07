"""
AES-ECB 解密脚本

使用方法:
    mitmdump -p 9090 -s aes_ecb.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=data key=1234567890123456

参数说明:
    -p 9090: 监听端口
    -s aes_ecb.py: 指定脚本文件
    --mode upstream:http://127.0.0.1:8080: 指定代理服务器
    --ssl-insecure: 忽略 SSL 证书验证
    field: 需要解密的字段名称，多个字段用逗号分隔
    key: AES密钥，必须是16字节(128位)、24字节(192位)或32字节(256位)

注意：ECB模式不需要IV，但安全性较低，建议使用CBC或GCM模式
"""

import sys
from mitmproxy import http
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import logging
import json
from urllib.parse import parse_qs, urlencode

# 配置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_decryption_fields():
    """获取解密配置"""
    all_args = sys.argv[1:]
    decryption_fields = []
    key = None

    for arg in all_args:
        if not arg.startswith('-'):
            if 'key=' in arg:
                key = arg.split('=')[1]
            elif 'field=' in arg:  # 明确检查 field= 前缀
                fields = arg.split('=')[1]
                decryption_fields = [field.strip() for field in fields.split(',') if field.strip()]

    if not key:
        raise ValueError("必须提供key参数")
    if len(key) not in [16, 24, 32]:
        raise ValueError("AES密钥必须是16/24/32字节长度")

    logging.info(f"需要解密的字段: {decryption_fields}")
    return decryption_fields, key

class AesEcbDecryptInterceptor:
    def __init__(self, decryption_fields, key):
        self.decryption_fields = decryption_fields
        self.key = key.encode('utf-8')

    def decrypt_value(self, encrypted_text: str) -> str:
        """解密单个值"""
        try:
            encrypted_data = base64.b64decode(encrypted_text)
            cipher = AES.new(self.key, AES.MODE_ECB)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            logging.error(f"解密失败: {e}")
            return encrypted_text

    def process_json_data(self, json_data: dict) -> tuple[dict, bool]:
        """处理JSON数据"""
        modified = False
        for field in self.decryption_fields:
            if field in json_data:
                try:
                    encrypted_value = json_data[field]
                    logging.info(f"JSON字段 {field} 待解密值: {encrypted_value}")
                    decrypted_value = self.decrypt_value(encrypted_value)
                    
                    try:
                        # 尝试将解密后的字符串解析为 JSON 对象
                        json_data[field] = json.loads(decrypted_value)
                    except json.JSONDecodeError:
                        # 如果不是有效的 JSON，则保持为字符串
                        json_data[field] = decrypted_value
                    
                    modified = True
                    logging.info(f"JSON字段 {field} 解密完成")
                except Exception as e:
                    logging.error(f"解密字段 {field} 失败: {e}")
        return json_data, modified

    def process_form_data(self, form_data: str) -> tuple[str, bool]:
        """处理表单数据"""
        params = parse_qs(form_data, keep_blank_values=True)
        modified = False

        for field in self.decryption_fields:
            if field in params:
                try:
                    values = params[field]
                    if isinstance(values, list):
                        decrypted_values = []
                        for value in values:
                            logging.info(f"表单字段 {field} 待解密值: {value}")
                            decrypted_values.append(self.decrypt_value(value))
                        params[field] = decrypted_values
                    else:
                        logging.info(f"表单字段 {field} 待解密值: {values}")
                        params[field] = self.decrypt_value(values)
                    modified = True
                    logging.info(f"表单字段 {field} 解密完成")
                except Exception as e:
                    logging.error(f"解密字段 {field} 失败: {e}")

        for key in params:
            if isinstance(params[key], list) and len(params[key]) == 1:
                params[key] = params[key][0]

        return urlencode(params), modified

    def request(self, flow: http.HTTPFlow) -> None:
        """处理请求"""
        try:
            content_type = flow.request.headers.get("Content-Type", "")
            logging.info("=" * 50)
            logging.info(f"请求URL: {flow.request.pretty_url}")
            logging.info(f"请求方法: {flow.request.method}")
            logging.info(f"Content-Type: {content_type}")

            # 显示原始请求数据包
            logging.info(f"原始请求数据包: {flow.request.content.decode('utf-8')}")

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
                logging.info("\n解密后的请求数据包:")
                logging.info(f"{flow.request.content.decode('utf-8')}")

            logging.info("=" * 50)

        except Exception as e:
            logging.error(f"处理请求失败: {e}")
            import traceback
            logging.error(traceback.format_exc())

# 获取解密配置
decryption_fields, key = get_decryption_fields()

# 注册插件
addons = [AesEcbDecryptInterceptor(decryption_fields, key)]