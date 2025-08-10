"""
AES-ECB 双向加解密脚本-已测试√

使用方法:
    解密模式: mitmdump -p 8888 -s aes_ecb.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password key=your_key

参数说明:
    field: 需要处理的字段，多个字段用逗号分隔
    key: AES密钥，长度必须为16、24或32字节

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段处理
    3. both模式：请求解密，响应加密（实现双向代理链）
"""

import os
import sys
import base64
from typing import Dict, Any
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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
    for arg in sys.argv:
        if arg.startswith('key='):
            key = arg.replace('key=', '').strip()
    
    if not key:
        raise ValueError("必须提供key参数")
    
    key_bytes = key.encode('utf-8')
    if len(key_bytes) not in [16, 24, 32]:
        raise ValueError(f"无效的AES密钥长度: {len(key_bytes)}字节，应为16/24/32字节")
    
    return key_bytes

class AesEcbBothInterceptor(BothInterceptor):
    """AES-ECB 双向加解密拦截器"""
    
    def __init__(self):
        script_name = os.path.splitext(os.path.basename(__file__))[0]
        self.key = get_aes_config()
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
            
            cipher = AES.new(self.key, AES.MODE_ECB)
            
            if current_mode == 'decrypt':
                # 解密逻辑
                if not value or not value.strip():
                    return value
                try:
                    encrypted_data = base64.b64decode(value)
                    if len(encrypted_data) % AES.block_size != 0:
                        return value
                    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
                    return decrypted_data.decode('utf-8')
                except:
                    return value
            else:
                # 加密逻辑
                try:
                    value = value.strip('"').strip("'")
                    padded = pad(value.encode('utf-8'), AES.block_size)
                    encrypted = cipher.encrypt(padded)
                    return base64.b64encode(encrypted).decode('utf-8')
                except:
                    return value
                    
        except Exception as e:
            self.logger.log(None, f"处理失败: {str(e)}")
            return value

# 创建拦截器实例
interceptor = AesEcbBothInterceptor()

# 注册插件
addons = [interceptor] 