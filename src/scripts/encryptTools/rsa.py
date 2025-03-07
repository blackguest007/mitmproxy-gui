"""
RSA 加密脚本

使用方法:
    mitmdump -p 8888 -s rsa.py --ssl-insecure field=password key=rsa_public_key.pem
    mitmdump -p 8888 -s rsa.py --ssl-insecure field=password,username key=rsa_public_key.pem

参数说明:
    -p 8888: 监听端口
    -s rsa.py: 指定脚本文件
    --ssl-insecure: 忽略 SSL 证书验证
    password: 单个加密字段
    password,username: 多个加密字段，用逗号分隔
    public_key: RSA公钥文件路径(.pem)或Base64格式的公钥

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段加密
    3. 加密结果使用 Base64 编码
    4. 公钥支持文件路径(.pem)或Base64格式
"""

import sys
import os
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

from src.otherTools.QueryStringParser import QueryStringParser

# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_encryption_fields():
    """
    从命令行参数获取加密配置
    
    Returns:
        tuple: (加密字段列表, 公钥字符串)
    """
    all_args = sys.argv[1:]
    encryption_fields = []
    public_key_str = None
    script_args = []

    # 找到 --ssl-insecure 之后的参数
    for i, arg in enumerate(all_args):
        if arg == '--ssl-insecure':
            script_args = all_args[i+1:]
            break

    # 只处理实际的脚本参数
    for arg in script_args:
        if 'key=' in arg:
            key_path = arg.split('=', 1)[1].strip()
            if key_path.endswith('.pem'):
                try:
                    key_path = key_path.strip('"').strip("'")
                    key_path = os.path.normpath(key_path)
                    
                    with open(key_path, 'r') as f:
                        public_key_str = f.read().strip()
                        logging.info(f"成功读取公钥文件: {key_path}")
                except Exception as e:
                    logging.error(f"读取公钥文件失败: {e}")
                    raise
            else:
                public_key_str = key_path
        elif not '=' in arg and not arg.endswith('.py'):
            # 只添加非选项的参数作为加密字段
            fields = [field.strip() for field in arg.split(',') if field.strip()]
            encryption_fields.extend(fields)

    # 如果没有指定加密字段，使用默认值
    if not encryption_fields:
        encryption_fields = ['password']

    logging.info(f"需要加密的字段: {encryption_fields}")
    if public_key_str:
        logging.info("公钥已加载")
    else:
        logging.error("未找到有效的公钥")
        
    return encryption_fields, public_key_str

# 获取加密配置
encryption_fields, public_key_str = get_encryption_fields()

class RsaEncryptInterceptor:
    """RSA 加密拦截器"""
    
    def __init__(self, encryption_fields, public_key_str):
        """
        初始化加密器
        
        Args:
            encryption_fields (list): 需要加密的字段名称列表
            public_key_str (str): RSA公钥字符串
        """
        self.encryption_fields = encryption_fields
        self.cipher = None
        
        try:
            if public_key_str:
                # 检查公钥内容是否已经是PEM格式
                if "-----BEGIN PUBLIC KEY-----" not in public_key_str:
                    # 如果不是PEM格式，进行转换
                    public_key_str = ("-----BEGIN PUBLIC KEY-----\n" +
                                    "\n".join(textwrap.wrap(public_key_str.strip(), 64)) +
                                    "\n-----END PUBLIC KEY-----")
                
                # 尝试加载公钥
                try:
                    public_key = RSA.importKey(public_key_str)
                    self.cipher = PKCS1_v1_5.new(public_key)
                    logging.info("成功加载公钥")
                except Exception as e:
                    logging.error(f"公钥格式错误: {e}")
                    logging.debug(f"公钥内容:\n{public_key_str}")
                    raise
            else:
                logging.error("未提供公钥")
        except Exception as e:
            logging.error(f"加载公钥失败: {e}")
            self.cipher = None

    def encrypt_value(self, plain_text: str) -> str:
        """
        加密单个值
        
        Args:
            plain_text (str): 待加密的文本
            
        Returns:
            str: Base64编码的加密结果
        """
        if not self.cipher:
            logging.warning("加密器未初始化，返回原始值")
            return plain_text
        try:
            encrypted_bytes = self.cipher.encrypt(plain_text.encode('utf-8'))
            return base64.b64encode(encrypted_bytes).decode('utf-8')
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
        """处理表单数据
        
        Args:
            form_data (str): 原始表单数据
            
        Returns:
            tuple[str, bool]: (处理后的数据, 是否被修改)
        """
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
        """处理请求"""
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
addons = [RsaEncryptInterceptor(encryption_fields, public_key_str)]
