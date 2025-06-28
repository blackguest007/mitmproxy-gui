"""
SM4 解密脚本-已测试√

使用方法:
    mitmdump -p 8888 -s sm4.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password key=your_key iv=your_iv

参数说明:
    field: 需要处理的字段，多个字段用逗号分隔
    key: SM4密钥，长度必须为16字节
    iv: 初始化向量，长度必须为16字节

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段处理
    3. 密钥长度必须符合要求
    4. 解密前的数据需要是Base64编码

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段处理
    3. 密钥长度必须符合要求
    4. 解密前的数据需要是Base64编码
    5. 支持上游代理模式，可以将请求转发到其他代理服务器
"""

import os
import sys
from typing import Dict, Any, Tuple
from mitmproxy import http
import base64
from gmssl import sm4
from urllib.parse import unquote

# 添加父目录到 Python 路径
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from common.utils import get_processing_fields, is_valid_base64
from common.interceptor import BaseInterceptor

def pkcs7_pad(data: bytes) -> bytes:
    """PKCS#7填充函数"""
    padding_len = 16 - (len(data) % 16)
    return data + bytes([padding_len] * padding_len)

def is_pkcs7_padded(data: bytes) -> bool:
    """检查数据是否使用PKCS#7填充"""
    if len(data) % 16 != 0:  # 长度必须是16的倍数
        return False
    padding_len = data[-1]
    if padding_len > 16 or padding_len == 0:  # 填充长度必须在1-16之间
        return False
    # 检查最后padding_len个字节是否都是padding_len
    return data[-padding_len:] == bytes([padding_len] * padding_len)

def pkcs7_unpad(padded_data: bytes) -> bytes:
    """PKCS#7去填充函数"""
    if not is_pkcs7_padded(padded_data):
        return padded_data
    padding_len = padded_data[-1]
    return padded_data[:-padding_len]

def sm4_cbc_decrypt(key: bytes, iv: bytes, encrypted_data: bytes) -> bytes:
    """SM4 CBC解密（GM/T 0002-2012标准）"""
    cipher = sm4.CryptSM4()
    cipher.set_key(key, sm4.SM4_DECRYPT)
    decrypted_padded = cipher.crypt_cbc(iv, encrypted_data)
    return pkcs7_unpad(decrypted_padded)

def get_sm4_config() -> Tuple[bytes, bytes]:
    """获取SM4配置"""
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
    
    # 转换为字节类型
    key_bytes = key.encode('utf-8')
    iv_bytes = iv.encode('utf-8')
    
    # 验证密钥和IV长度
    if len(key_bytes) != 16:
        raise ValueError(f"无效的SM4密钥长度: {len(key_bytes)}字节，应为16字节")
    if len(iv_bytes) != 16:
        raise ValueError(f"无效的IV长度: {len(iv_bytes)}字节，应为16字节")
    
    return key_bytes, iv_bytes

class SM4DecryptInterceptor(BaseInterceptor):
    """SM4 解密拦截器"""
    
    def __init__(self, key: bytes, iv: bytes):
        """
        初始化SM4解密拦截器
        
        Args:
            key: SM4密钥
            iv: 初始化向量
        """
        script_name = os.path.splitext(os.path.basename(__file__))[0]
        super().__init__(
            script_name=script_name,
            mode="decrypt",
            processing_fields=get_processing_fields(),
            process_func=self.decrypt_value
        )
        self.key = key
        self.iv = iv

    def decrypt_value(self, value: str, url: str, field: str, full_json: Dict[str, Any] = None, form_data: str = "") -> str:
        """
        解密SM4加密的值
        
        Args:
            value: 要解密的值
            url: 请求URL
            field: 字段名
            full_json: 完整的JSON数据（如果是JSON格式）
            form_data: 完整的表单数据（如果是表单格式）
            
        Returns:
            str: 解密后的值
        """
        try:
            # 1. 处理表单数据中的空格（将空格替换回+号）
            if form_data:
                value = value.replace(' ', '+')
            
            # 2. 检查是否需要URL解码
            if '%' in value or '+' in value:
                value = unquote(value)
            
            # 3. 检查是否是有效的Base64编码
            if not is_valid_base64(value):
                self.logger.log(None, f"无效的Base64编码: {value}")
                return value
                
            # 4. Base64解码
            try:
                encrypted_data = base64.b64decode(value)
            except Exception as e:
                self.logger.log(None, f"Base64解码错误: {str(e)}")
                return value
            
            # 5. SM4解密
            try:
                decrypted_data = sm4_cbc_decrypt(self.key, self.iv, encrypted_data)
            except Exception as e:
                self.logger.log(None, f"SM4解密错误: {str(e)}")
                return value
            
            # 6. UTF-8解码
            try:
                decrypted_text = decrypted_data.decode('utf-8')
                
                if not decrypted_text:
                    self.logger.log(None, "解密结果为空字符串")
                    return value
                
                return decrypted_text
            except Exception as e:
                self.logger.log(None, f"UTF-8解码错误: {str(e)}")
                return value
                
        except Exception as e:
            self.logger.log(None, f"解密过程错误: {str(e)}")
            return value

# 获取配置
try:
    key, iv = get_sm4_config()
except Exception as e:
    print(f"配置错误: {str(e)}", file=sys.stderr)
    sys.exit(1)

# 创建拦截器实例
interceptor = SM4DecryptInterceptor(key, iv)

# 注册插件
addons = [interceptor] 