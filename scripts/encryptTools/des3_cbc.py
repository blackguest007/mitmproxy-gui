"""
<<<<<<< HEAD
DES3-CBC 加密脚本-已测试√√√
=======
DES3-CBC 加密脚本-已测试
>>>>>>> 003e959c53f0a3ebe65ba51c3c236e85da3c6263

使用方法:
    mitmdump -p 8888 -s des3_cbc.py --ssl-insecure field=password key=your_key iv=your_iv
    mitmdump -p 8888 -s des3_cbc.py --ssl-insecure field=password,username key=your_key iv=your_iv

参数说明:
    field: 需要处理的字段，多个字段用逗号分隔
    key: DES3 密钥（24字节）
    iv: 初始化向量（8字节）

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段加密
    3. 加密结果会进行 Base64 编码
    4. 日志文件保存在 src/logs 目录下，格式为: encrypt_des3_cbc_时间戳.log
"""

import os
import sys
import base64
from typing import Dict, Any
<<<<<<< HEAD
from unittest import installHandler
=======
>>>>>>> 003e959c53f0a3ebe65ba51c3c236e85da3c6263
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad
import json

# 添加父目录到 Python 路径
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from common.utils import get_processing_fields
from common.interceptor import BaseInterceptor

def get_des3_config():
    key = None
    iv = None
    for arg in sys.argv:
        if arg.startswith('key='):
            key = arg.replace('key=', '').strip()
        elif arg.startswith('iv='):
            iv = arg.replace('iv=', '').strip()
    if not key:
        raise ValueError("请指定 DES3 密钥，例如: key=your_key")
    if not iv:
        raise ValueError("请指定初始化向量，例如: iv=your_iv")
    return key.encode('utf-8'), iv.encode('utf-8')

class Des3CbcEncryptInterceptor(BaseInterceptor):
    """DES3-CBC 加密拦截器"""
    def __init__(self):
        script_name = os.path.splitext(os.path.basename(__file__))[0]
        self.key, self.iv = get_des3_config()
        super().__init__(
            script_name=script_name,
            mode="encrypt",
            processing_fields=get_processing_fields(),
            process_func=self.encrypt_value
        )

    def encrypt_value(self, value: str, url: str, field: str, full_json: Dict[str, Any] = None, form_data: str = "") -> str:
        """
        对指定字段进行 DES3-CBC 加密
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
<<<<<<< HEAD
            # 保证 value 是 dict 或 str
            if isinstance(value,dict):

                value_bytes = value.strip('"').strip("'")
            elif isinstance(value,str):
                value_bytes=value.encode('utf-8')
            else:
                if isinstance(value, (dict, list)):
                    value_bytes = json.dumps(value).encode('utf-8')
                else:
                    value_bytes = str(value).encode('utf-8')

            cipher = DES3.new(self.key, DES3.MODE_CBC, self.iv)
            ciphertext = cipher.encrypt(pad(value_bytes, DES3.block_size))
            return base64.b64encode(ciphertext).decode('utf-8')
        except Exception as e:
            self.logger.log(None, f"DES3-CBC加密失败: {str(e)}")
            return value if isinstance(value, str) else str(value)
=======
            value = value.strip('"').strip("'")
            cipher = DES3.new(self.key, DES3.MODE_CBC, self.iv)
            ciphertext = cipher.encrypt(pad(value.encode('utf-8'), DES3.block_size))
            return base64.b64encode(ciphertext).decode('utf-8')
        except Exception as e:
            self.logger.log(None, f"DES3-CBC加密失败: {str(e)}")
            return value
>>>>>>> 003e959c53f0a3ebe65ba51c3c236e85da3c6263

# 创建拦截器实例
interceptor = Des3CbcEncryptInterceptor()

# 注册插件
addons = [interceptor]
