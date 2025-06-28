"""
<<<<<<< HEAD
SM4 加密脚本-已测试√√√

使用方法:
    mitmdump -p 8888 -s sm4.py --ssl-insecure field=password key=your_key iv=your_iv

参数说明:
    field: 需要处理的字段，多个字段用逗号分隔
    key: SM4密钥，长度必须为16字节
    iv: 初始化向量，长度必须为16字节

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段处理
    3. 密钥长度必须符合要求
    4. 只加密字符串类型字段
"""

import os
import sys
from typing import Dict, Any, Optional, Tuple
from mitmproxy import http
import base64
from gmssl import sm4

# 添加父目录到 Python 路径
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from common.utils import get_processing_fields
from common.interceptor import BaseInterceptor

def pkcs7_pad(data: bytes) -> bytes:
    """PKCS#7填充函数"""
    padding_len = 16 - (len(data) % 16)
    return data + bytes([padding_len] * padding_len)


def sm4_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """SM4 CBC加密（与 sm-crypto 库保持一致）"""
    cipher = sm4.CryptSM4()
    cipher.set_key(key, sm4.SM4_ENCRYPT)
    # 使用 PKCS7 填充，与 sm-crypto 库保持一致
    padded_data = pkcs7_pad(data)
    return cipher.crypt_cbc(iv, padded_data)

def hex_to_bytes(hex_string: str) -> bytes:
    """将十六进制字符串转换为字节"""
    return bytes.fromhex(hex_string)

def bytes_to_hex(data: bytes) -> str:
    """将字节转换为十六进制字符串"""
    return data.hex()

def get_sm4_config() -> Tuple[bytes, bytes]:
    """获取SM4配置（与解密脚本保持一致）"""
    key = None
    iv = None
    for arg in sys.argv:
        if arg.startswith('key='):
            key = arg.replace('key=', '').strip()
        elif arg.startswith('iv='):
            iv = arg.replace('iv=', '').strip()
    
    if not key:
        raise ValueError("必须提供key参数")
    if not iv:
        raise ValueError("必须提供iv参数")
    
    # 使用 UTF-8 编码（与解密脚本保持一致）
    key_bytes = key.encode('utf-8')
    iv_bytes = iv.encode('utf-8')
    
    # 验证密钥和IV长度
    if len(key_bytes) != 16:
        raise ValueError(f"无效的SM4密钥长度: {len(key_bytes)}字节，应为16字节")
    if len(iv_bytes) != 16:
        raise ValueError(f"无效的IV长度: {len(iv_bytes)}字节，应为16字节")
    
    return key_bytes, iv_bytes

class SM4EncryptInterceptor(BaseInterceptor):
    """SM4 CBC 加密拦截器"""
    
    def __init__(self, key: bytes, iv: bytes):
        """
        初始化SM4加密拦截器
        
        Args:
            key: SM4密钥
            iv: 初始化向量
        """
        script_name = os.path.splitext(os.path.basename(__file__))[0]
        super().__init__(
            script_name=script_name,
            mode="encrypt",
            processing_fields=get_processing_fields(),
            process_func=self.encrypt_value
        )
        self.key = key
        self.iv = iv

    def encrypt_value(self, value: str, url: str, field: str, full_json: Optional[Dict[str, Any]] = None, form_data: str = "") -> str:
        """
        加密SM4值（正确的加密流程）
        
        Args:
            value: 要加密的值
            url: 请求URL
            field: 字段名
            full_json: 完整的JSON数据（如果是JSON格式）
            form_data: 完整的表单数据（如果是表单格式）
=======
SM4 加密脚本

使用方法:
    mitmdump -p 8888 -s sm4.py --ssl-insecure field=password key=your_key
    mitmdump -p 8888 -s sm4.py --ssl-insecure field=password,username key=your_key

参数说明:
    -p 8888: 监听端口
    -s sm4.py: 指定脚本文件
    --ssl-insecure: 忽略 SSL 证书验证
    field=password: 单个加密字段
    field=password,username: 多个加密字段，用逗号分隔
    key=your_key: SM4 密钥（16字节）

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段加密
    3. 加密结果会进行 Base64 编码
    4. 日志文件保存在 logs 目录下，格式为: encrypt_sm4_时间戳.log
"""

import sys
import os
import base64
from typing import Dict, Any, List
from gmssl import sm4, func

# 添加父目录到系统路径
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from common.interceptor import BaseInterceptor

def get_encryption_config() -> Dict[str, Any]:
    """从命令行参数获取加密配置"""
    config = {
        'fields': [],
        'key': None
    }
    
    for arg in sys.argv:
        if arg.startswith('field='):
            config['fields'] = [field.strip() for field in arg.replace('field=', '').split(',') if field.strip()]
        elif arg.startswith('key='):
            config['key'] = arg.replace('key=', '').strip()
            
    return config

class Sm4EncryptInterceptor(BaseInterceptor):
    """SM4 加密拦截器"""
    
    def __init__(self):
        """初始化拦截器"""
        config = get_encryption_config()
        if not config['fields']:
            raise ValueError("请指定要加密的字段，例如: field=password")
        if not config['key']:
            raise ValueError("请指定 SM4 密钥，例如: key=your_key")
            
        try:
            # 创建 SM4 加密器
            self.crypt_sm4 = sm4.CryptSM4()
            # 设置密钥
            self.crypt_sm4.set_key(config['key'].encode('utf-8'), sm4.SM4_ENCRYPT)
        except Exception as e:
            raise ValueError(f"无效的 SM4 密钥: {str(e)}")
        
        super().__init__(
            script_name="sm4",
            mode="encrypt",
            processing_fields=config['fields'],
            process_func=self.encrypt_value
        )
        
    def encrypt_value(self, value: str, url: str, field: str, full_json: Dict[str, Any] = None, form_data: str = "") -> str:
        """
        对指定字段进行 SM4 加密
        
        Args:
            value: 要加密的值
            url: 请求 URL
            field: 字段名
            full_json: 完整的 JSON 数据（如果是 JSON 请求）
            form_data: 完整的表单数据（如果是表单请求）
>>>>>>> 003e959c53f0a3ebe65ba51c3c236e85da3c6263
            
        Returns:
            str: 加密后的值（Base64编码）
        """
        try:
<<<<<<< HEAD
            if not isinstance(value, str):
                raise TypeError(f"SM4加密仅支持字符串类型，收到类型: {type(value)}")
            
            self.logger.log(url, f"SM4加密前的值: {value}")
            
            # 1. 原始数据 -> UTF-8编码 -> 二进制字节
            data_bytes = value.encode('utf-8')
            self.logger.log(url, f"UTF-8编码后字节数: {len(data_bytes)}")
            
            # 2. 二进制字节 -> PKCS7填充 -> 填充后的二进制字节
            padded_data = pkcs7_pad(data_bytes)
            self.logger.log(url, f"PKCS7填充后字节数: {len(padded_data)}")
            
            # 3. 填充后的二进制字节 -> SM4加密 -> 加密后的二进制字节
            try:
                encrypted_bytes = sm4_cbc_encrypt(self.key, self.iv, padded_data)
                self.logger.log(url, f"SM4加密后字节数: {len(encrypted_bytes)}")
                
                # 4. 只取前32字节（匹配浏览器 JS 的行为）
                encrypted_bytes = encrypted_bytes[:32]
                self.logger.log(url, f"截取后字节数: {len(encrypted_bytes)}")
                
            except Exception as e:
                self.logger.log(None, f"SM4加密错误: {str(e)}")
                return value
            
            # 5. 加密后的二进制字节 -> 直接 Base64 编码
            try:
                encrypted = base64.b64encode(encrypted_bytes).decode('utf-8')
                self.logger.log(url, f"SM4加密后: {encrypted}")
                return encrypted
            except Exception as e:
                self.logger.log(None, f"Base64编码错误: {str(e)}")
                return value
                
        except Exception as e:
            self.logger.log(None, f"加密过程错误: {str(e)}")
            return value

# 获取配置
try:
    key, iv = get_sm4_config()
except Exception as e:
    print(f"配置错误: {str(e)}", file=sys.stderr)
    sys.exit(1)

# 创建拦截器实例
interceptor = SM4EncryptInterceptor(key, iv)

# 注册插件
addons = [interceptor] 
=======
            # 移除可能的引号
            value = value.strip('"').strip("'")
            # 加密数据
            ciphertext = self.crypt_sm4.crypt_ecb(value.encode('utf-8'))
            # Base64 编码
            return base64.b64encode(ciphertext).decode('utf-8')
        except Exception as e:
            self.logger.log(None, f"SM4加密失败: {str(e)}")
            return value

# 创建拦截器实例
interceptor = Sm4EncryptInterceptor()

# 注册请求和响应处理函数
def request(flow):
    interceptor.request(flow)

def response(flow):
    interceptor.response(flow)

def done():
    interceptor.done() 
>>>>>>> 003e959c53f0a3ebe65ba51c3c236e85da3c6263
