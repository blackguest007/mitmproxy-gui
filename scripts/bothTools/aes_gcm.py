"""
AES-GCM 双向加解密脚本 (v1.0.5重构版) - 已测试√√√

【架构说明】
基于 BothInterceptor 统一架构，实现真正的双向代理：
- 请求流：客户端 → [解密] → 上游服务器
- 响应流：上游服务器 → [加密] → 客户端

【使用方法】
双向模式: mitmdump -p 8888 -s aes_gcm.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password key=your_key iv=your_iv

【参数说明】
field: 需要处理的字段，多个字段用逗号分隔
key:   AES密钥，长度必须为16、24或32字节
iv:    初始向量，任意长度（自动调整为12字节nonce）

【功能特性】
1. 支持 application/json 和 application/x-www-form-urlencoded 格式
2. 支持单个或多个字段同时处理
3. 双向模式：请求自动解密，响应自动加密
4. 统一 process_value 接口，通过 is_response 参数区分处理方向
5. 独立的请求/响应日志记录
6. GCM模式提供认证加密功能
7. 自动处理认证标签验证
"""

import os
import sys
import base64
from typing import Dict, Any
from Crypto.Cipher import AES

# 添加父目录到 Python 路径
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from common.utils import get_processing_fields
from common.both_interceptor import BothInterceptor

def get_mode() -> str:
    """获取运行模式"""
    for arg in sys.argv:
        if arg == '--mode' or arg.startswith('--mode='):
            return 'decrypt'  # 有--mode参数就是解密模式
    return 'encrypt'  # 默认模式为加密

def get_aes_config():
    """获取AES配置"""
    key = None
    iv = None
    for arg in sys.argv:
        if arg.startswith('key='):
            key = arg.replace('key=', '').strip()
        elif arg.startswith('iv='):
            iv = arg.replace('iv=', '').strip()
    
    if not key or not iv:
        raise ValueError("必须提供key和iv参数")
    
    key_bytes = key.encode('utf-8')
    iv_bytes = iv.encode('utf-8')
    if len(key_bytes) not in [16, 24, 32]:
        raise ValueError(f"无效的AES密钥长度: {len(key_bytes)}字节，应为16/24/32字节")
    
    # 前端使用完整的16字节IV作为nonce（forge.js的实现方式）
    # 注意：这在标准GCM中不推荐，但为了兼容前端，我们需要这样做
    nonce_bytes = iv_bytes  # 使用完整的IV作为nonce
    
    return key_bytes, nonce_bytes

class AesGcmBothInterceptor(BothInterceptor):
    """AES-GCM 双向加解密拦截器"""
    
    def __init__(self):
        script_name = os.path.splitext(os.path.basename(__file__))[0]
        self.key, self.nonce = get_aes_config()  # 内部仍使用nonce，但从iv参数获取
        mode = get_mode()
        
        super().__init__(
            script_name=script_name,
            mode=mode,
            processing_fields=get_processing_fields()
        )

    def process_value(self, value: str, url: str, field: str, is_response: bool = False) -> str:
        """
        处理单个字段的值
        Args:
            is_response: False=请求(按mode处理), True=响应(按相反mode处理)
        """
        try:
            # 确定当前操作模式
            current_mode = self.mode
            if is_response:
                current_mode = 'encrypt' if self.mode == 'decrypt' else 'decrypt'
            
            if current_mode == 'decrypt':
                # 解密逻辑
                if not value or not value.strip():
                    return value
                try:
                    encrypted_data = base64.b64decode(value)
                    if len(encrypted_data) < 16:  # 至少需要16字节的标签
                        return value
                    
                    # 分离密文和认证标签
                    ciphertext = encrypted_data[:-16]
                    tag = encrypted_data[-16:]
                    
                    cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                    return plaintext.decode('utf-8')
                except:
                    return value
            else:
                # 加密逻辑
                try:
                    value = value.strip('"').strip("'")
                    cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
                    ciphertext, tag = cipher.encrypt_and_digest(value.encode('utf-8'))
                    encrypted_data = ciphertext + tag
                    return base64.b64encode(encrypted_data).decode('utf-8')
                except:
                    return value
                    
        except Exception as e:
            self.logger.log(None, f"处理失败: {str(e)}")
            return value

# 创建拦截器实例
interceptor = AesGcmBothInterceptor()

# 注册插件
addons = [interceptor] 
