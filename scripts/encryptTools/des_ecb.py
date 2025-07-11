"""
DES-ECB 加密脚本-已测试√√√

使用方法:
    mitmdump -p 8888 -s des_ecb.py --ssl-insecure field=password key=your_key
    mitmdump -p 8888 -s des_ecb.py --ssl-insecure field=password,username key=your_key

参数说明:
    field: 需要处理的字段，多个字段用逗号分隔
    key: DES 密钥（8字节）

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段加密
    3. 加密结果会进行 Base64 编码
    4. 日志文件保存在 src/logs 目录下，格式为: encrypt_des_ecb_时间戳.log
"""

import os
import sys
import base64
from typing import Dict, Any
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad

# 添加父目录到 Python 路径
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from common.utils import get_processing_fields
from common.interceptor import BaseInterceptor

def get_des_config():
    key = None
    for arg in sys.argv:
        if arg.startswith('key='):
            key = arg.replace('key=', '').strip()
    if not key:
        raise ValueError("请指定 DES 密钥，例如: key=your_key")
    return key.encode('utf-8')

class DesEcbEncryptInterceptor(BaseInterceptor):
    """DES-ECB 加密拦截器"""
    def __init__(self):
        script_name = os.path.splitext(os.path.basename(__file__))[0]
        self.key = get_des_config()
        super().__init__(
            script_name=script_name,
            mode="encrypt",
            processing_fields=get_processing_fields(),
            process_func=self.encrypt_value
        )

    def encrypt_value(self, value: str, url: str, field: str, full_json: Dict[str, Any] = None, form_data: str = "") -> str:
        """
        对指定字段进行 DES-ECB 加密
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
            value = value.strip('"').strip("'")
            cipher = DES.new(self.key, DES.MODE_ECB)
            ciphertext = cipher.encrypt(pad(value.encode('utf-8'), DES.block_size))
            return base64.b64encode(ciphertext).decode('utf-8')
        except Exception as e:
            self.logger.log(None, f"DES-ECB加密失败: {str(e)}")
            return value

# 创建拦截器实例
interceptor = DesEcbEncryptInterceptor()

# 注册插件
addons = [interceptor] 