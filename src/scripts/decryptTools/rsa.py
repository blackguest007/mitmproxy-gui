"""
RSA 解密脚本

使用方法:
    mitmdump -p 8888 -s rsa.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password private_key=rsa_private_key.pem
    mitmdump -p 8888 -s rsa.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password,username private_key=rsa_private_key.pem

参数说明:
    -p 8888: 监听端口
    -s rsa.py: 指定脚本文件
    --mode upstream:http://127.0.0.1:8080: 指定代理服务器
    --ssl-insecure: 忽略 SSL 证书验证
    field: 单个解密字段或多个解密字段，用逗号分隔
    private_key: RSA私钥文件路径(.pem)或Base64格式的私钥

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段解密
    3. 解密前的数据需要是 Base64 编码
    4. 私钥支持文件路径(.pem)或Base64格式
"""

import sys
import os
import urllib
from mitmproxy import ctx
from mitmproxy import http
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64
import json
import logging
from urllib.parse import parse_qs, urlencode
import textwrap

# 修改导入路径的设置
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))
sys.path.insert(0, project_root)


# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_decryption_fields():
    """从命令行参数获取解密配置"""
    all_args = sys.argv[1:]
    decryption_fields = []
    private_key_str = None

    for arg in all_args:
        if not arg.startswith('-'):
            if 'private_key=' in arg:
                key_path = arg.split('=', 1)[1].strip()
                if key_path.endswith('.pem'):
                    try:
                        key_path = key_path.strip('"').strip("'")
                        key_path = os.path.normpath(key_path)
                        
                        with open(key_path, 'r') as f:
                            private_key_str = f.read().strip()
                            logging.info(f"成功读取私钥文件: {key_path}")
                    except Exception as e:
                        logging.error(f"读取私钥文件失败: {e}")
                        raise
            elif 'field=' in arg:
                fields = arg.split('=', 1)[1].strip().split(',')
                decryption_fields.extend([field.strip() for field in fields if field.strip()])
            else:
                try:
                    float(arg)
                except ValueError:
                    continue

    if not decryption_fields:
        decryption_fields = ['password']

    logging.info(f"需要解密的字段: {decryption_fields}")
    if private_key_str:
        logging.info("私钥已加载")
    else:
        logging.error("未找到有效的私钥")
        
    return decryption_fields, private_key_str

class RsaDecryptInterceptor:
    def __init__(self, decryption_fields, private_key_str):
        """
        初始化解密器
        
        Args:
            decryption_fields (list): 需要解密的字段名称列表
            private_key_str (str): RSA私钥字符串
        """
        self.decryption_fields = decryption_fields
        self.cipher = None
        
        try:
            if private_key_str:
                if not private_key_str.startswith('-----BEGIN RSA PRIVATE KEY-----'):
                    private_key_str = ("-----BEGIN RSA PRIVATE KEY-----\n" +
                                     "\n".join(textwrap.wrap(private_key_str, 64)) +
                                     "\n-----END RSA PRIVATE KEY-----")
                private_key = RSA.importKey(private_key_str)
                self.cipher = PKCS1_v1_5.new(private_key)
                logging.info("成功加载私钥")
            else:
                logging.error("未提供私钥")
        except Exception as e:
            logging.error(f"加载私钥失败: {e}")
            self.cipher = None

    def decrypt_value(self, encrypted_text: str) -> str:
        """解密单个值"""
        if not self.cipher:
            logging.warning("解密器未初始化，返回原始值")
            return encrypted_text
        try:
            # Base64解码
            encrypted_bytes = base64.b64decode(encrypted_text)
            # RSA解密
            decrypted_bytes = self.cipher.decrypt(encrypted_bytes, None)
            # 转换为字符串
            return decrypted_bytes.decode('utf-8')
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

    def request(self, flow: http.HTTPFlow) -> None:
        """处理请求"""
        if not self.cipher:
            return

        try:
            content_type = flow.request.headers.get("Content-Type", "")
            logging.info("=" * 50)
            logging.info(f"请求URL: {flow.request.pretty_url}")
            logging.info(f"请求方法: {flow.request.method}")
            logging.info(f"Content-Type: {content_type}")

            if flow.request.content:
                req = flow.request.get_text()
                logging.info(f"原始请求数据: {req}")

                if "application/json" in content_type:
                    try:
                        # 处理JSON格式
                        json_data = json.loads(req)
                        modified = False
                        
                        # 处理 JSON 数据
                        json_data, modified = self.process_json_data(json_data)
                        
                        if modified:
                            # 更新请求内容
                            flow.request.text = json.dumps(json_data)
                            logging.info(f"解密后的JSON数据: {flow.request.text}")
                            flow.request.headers["Content-Length"] = str(len(flow.request.content))
                        
                    except json.JSONDecodeError as e:
                        logging.error(f"JSON解析失败: {e}")

                elif "application/x-www-form-urlencoded" in content_type:
                    try:
                        params = parse_qs(req, keep_blank_values=True)
                        modified = False

                        for field in self.decryption_fields:
                            if field in params:
                                try:
                                    values = params[field]
                                    if isinstance(values, list):
                                        decrypted_values = []
                                        for value in values:
                                            # URL解码
                                            decoded_value = urllib.parse.unquote(value)
                                            logging.info(f"字段 {field} 待解密值: {decoded_value}")
                                            decrypted_values.append(self.decrypt_value(decoded_value))
                                        params[field] = decrypted_values
                                    else:
                                        # URL解码
                                        decoded_value = urllib.parse.unquote(values)
                                        logging.info(f"字段 {field} 待解密值: {decoded_value}")
                                        params[field] = self.decrypt_value(decoded_value)
                                    modified = True
                                    logging.info(f"字段 {field} 解密完成")
                                except Exception as e:
                                    logging.error(f"解密字段 {field} 失败: {e}")

                        if modified:
                            # 处理单值列表
                            for key in params:
                                if isinstance(params[key], list) and len(params[key]) == 1:
                                    params[key] = params[key][0]
                            
                            new_content = urlencode(params, doseq=True)
                            flow.request.content = new_content.encode('utf-8')
                            logging.info(f"解密后的表单数据: {new_content}")
                            flow.request.headers["Content-Length"] = str(len(flow.request.content))

                    except Exception as e:
                        logging.error(f"处理表单数据失败: {e}")
                        import traceback
                        logging.error(traceback.format_exc())

                logging.info("=" * 50)

        except Exception as e:
            logging.error(f"处理请求失败: {e}")
            import traceback
            logging.error(traceback.format_exc())

# 获取解密配置
decryption_fields, private_key_str = get_decryption_fields()

# 注册插件
addons = [RsaDecryptInterceptor(decryption_fields, private_key_str)]