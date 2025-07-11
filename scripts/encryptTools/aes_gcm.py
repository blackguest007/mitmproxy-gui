"""
AES-GCM 加密脚本-已测试√√√

使用方法:
    mitmdump -p 8888 -s aes_gcm.py --ssl-insecure field=password key=your_key iv=your_iv
    mitmdump -p 8888 -s aes_gcm.py --ssl-insecure field=password,username key=your_key iv=your_iv

参数说明:
    -p 8888: 监听端口
    -s aes_gcm.py: 指定脚本文件
    --ssl-insecure: 忽略 SSL 证书验证
    field=password: 单个加密字段
    field=password,username: 多个加密字段，用逗号分隔
    key=your_key: AES 密钥（16/24/32字节）
    iv=your_iv: 初始化向量（12字节）

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段加密
    3. 加密结果会进行 Base64 编码
    4. 日志文件保存在 logs 目录下，格式为: encrypt_aes_gcm_时间戳.log
"""

import sys
import os
import base64
from typing import Dict, Any, List
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# 添加父目录到系统路径
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from common.interceptor import BaseInterceptor

def get_encryption_config() -> Dict[str, Any]:
    """从命令行参数获取加密配置"""
    config = {
        'fields': [],
        'key': None,
        'iv': None
    }
    
    for arg in sys.argv:
        if arg.startswith('field='):
            config['fields'] = [field.strip() for field in arg.replace('field=', '').split(',') if field.strip()]
        elif arg.startswith('key='):
            config['key'] = arg.replace('key=', '').strip()
        elif arg.startswith('iv='):
            config['iv'] = arg.replace('iv=', '').strip()
            
    return config

class AesGcmEncryptInterceptor(BaseInterceptor):
    """AES-GCM 加密拦截器"""
    
    def __init__(self):
        """初始化拦截器"""
        config = get_encryption_config()
        if not config['fields']:
            raise ValueError("请指定要加密的字段，例如: field=password")
        if not config['key']:
            raise ValueError("请指定 AES 密钥，例如: key=your_key")
        if not config['iv']:
            raise ValueError("请指定初始化向量，例如: iv=your_iv")
            
        self.key = config['key'].encode('utf-8')
        self.iv = config['iv'].encode('utf-8')
        
        super().__init__(
            script_name="aes_gcm",
            mode="encrypt",
            processing_fields=config['fields'],
            process_func=self.encrypt_value
        )
        
    def encrypt_value(self, value: str, url: str, field: str, full_json: Dict[str, Any] = None, form_data: str = "") -> str:
        """
        对指定字段进行 AES-GCM 加密
        
        Args:
            value: 要加密的值
            url: 请求 URL
            field: 字段名
            full_json: 完整的 JSON 数据（如果是 JSON 请求）
            form_data: 完整的表单数据（如果是表单请求）
            
        Returns:
            str: 加密后的值（Base64编码）
        """
        try:
            # 移除可能的引号
            value = value.strip('"').strip("'")
            # 创建 AES-GCM 加密器
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.iv)
            # 加密数据（GCM 不需要填充）
            ciphertext, tag = cipher.encrypt_and_digest(value.encode('utf-8'))
            # 组合密文和认证标签
            encrypted_data = ciphertext + tag
            # Base64 编码
            return base64.b64encode(encrypted_data).decode('utf-8')
        except Exception as e:
            self.logger.log(None, f"AES-GCM加密失败: {str(e)}")
            return value

# 创建拦截器实例
interceptor = AesGcmEncryptInterceptor()

# 注册插件
addons = [interceptor] 
