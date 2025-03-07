"""
AES-GCM 解密脚本

使用方法:
    mitmdump -p 8888 -s aes_gcm.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=data key=32byteslongsecretkeyforaes256!aa iv=16byteslongiv456

参数说明:
    -p 8888: 监听端口
    -s aes_gcm.py: 指定脚本文件
    --mode upstream:http://127.0.0.1:8080: 指定代理服务器
    --ssl-insecure: 忽略 SSL 证书验证
    field: 需要解密的字段名称，多个字段用逗号分隔
    key: AES密钥，必须是16字节(128位)、24字节(192位)或32字节(256位)
    iv: GCM模式的初始化向量，必须是16字节长度（与客户端保持一致）
"""

import sys
import os
from mitmproxy import http
from Crypto.Cipher import AES
import base64
import logging
import json
from urllib.parse import parse_qs, urlencode

# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_decryption_fields():
    """获取解密配置"""
    all_args = sys.argv[1:]
    decryption_fields = []
    key = None
    iv = None

    for arg in all_args:
        if not arg.startswith('-'):
            if 'key=' in arg:
                key = arg.split('=')[1]
            elif 'iv=' in arg:
                iv = arg.split('=')[1]
            elif 'field=' in arg:  # 明确检查 field= 前缀
                fields = arg.split('=')[1]
                decryption_fields = [field.strip() for field in fields.split(',') if field.strip()]

    if not key or not iv:
        raise ValueError("必须提供key和iv参数")
    if len(key) not in [16, 24, 32]:
        raise ValueError("AES密钥必须是16/24/32字节长度")
    if len(iv) != 16:  # 修改为16字节，与客户端保持一致
        raise ValueError("IV必须是16字节长度")

    logging.info(f"需要解密的字段: {decryption_fields}")
    return decryption_fields, key, iv

def get_fields():
    """获取需要处理的字段"""
    all_args = sys.argv
    fields = []
    for arg in all_args:
        if arg.startswith('field='):
            fields = [field.strip() for field in arg.replace('field=', '').split(',') if field.strip()]
            break
    return fields or ['password']  # 默认字段

# 获取所有参数
try:
    decryption_fields, key, iv = get_decryption_fields()
except Exception as e:
    logging.error(f"参数错误: {e}")
    sys.exit(1)

class AesGcmDecryptInterceptor:
    def __init__(self, decryption_fields, key, iv):
        self.decryption_fields = decryption_fields
        self.key = key.encode('utf-8')
        self.iv = iv.encode('utf-8')
        self.tag_length = 16  # GCM认证标签长度（字节）

    def decrypt_value(self, encrypted_text: str) -> str:
        """解密单个值"""
        try:
            # Base64解码
            encrypted_data = base64.b64decode(encrypted_text)
            
            # 分离密文和认证标签（与客户端一致）
            ciphertext = encrypted_data[:-self.tag_length]
            tag = encrypted_data[-self.tag_length:]
            
            # 创建解密器
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.iv)
            
            # 解密并验证
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            logging.error(f"解密失败: {e}")
            logging.error(f"密钥长度: {len(self.key)}")
            logging.error(f"IV长度: {len(self.iv)}")
            logging.error(f"加密数据长度: {len(encrypted_data)}")
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
            logging.info(f"原始请求数据包:\n{flow.request.method} {flow.request.pretty_url}")
            logging.info(f"Content-Type: {content_type}")
            logging.info(f"{flow.request.content.decode('utf-8')}")

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
                logging.info("\n解密后的请求数据包:")
                logging.info(f"{flow.request.content.decode('utf-8')}")

            logging.info("=" * 50)

        except Exception as e:
            logging.error(f"处理请求失败: {e}")
            import traceback
            logging.error(traceback.format_exc())

# 注册插件
addons = [AesGcmDecryptInterceptor(decryption_fields, key, iv)]