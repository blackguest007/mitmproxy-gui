"""
DES-CBC 加密脚本-已测试√√√

【支持数据格式】
1. application/json
2. application/x-www-form-urlencoded

【字段要求】
- 对指定字段（如 field=data）进行加密
- 字段类型可以为字符串或对象（dict/list），对象会自动序列化为字符串后加密

【常见错误及解决办法】
- JSON解析失败：通常是因为请求体不是合法 JSON，或字符串内容未正确转义
  解决办法：确保请求体为合法 JSON，字符串内容用 \" 正确转义

【使用方法】
mitmdump -p 8888 -s des_cbc.py --ssl-insecure field=password key=your_key iv=your_iv
mitmdump -p 8888 -s des_cbc.py --ssl-insecure field=password,username key=your_key iv=your_iv

【参数说明】
- field: 需要处理的字段，多个字段用逗号分隔
- key: DES 密钥（8字节）
- iv: 初始化向量（8字节）

【注意事项】
- 支持 application/json 和 application/x-www-form-urlencoded 格式
- 支持单个或多个字段加密
- 加密结果会进行 Base64 编码
- 日志文件保存在 src/logs 目录下，格式为: encrypt_des_cbc_时间戳.log
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
    iv = None
    for arg in sys.argv:
        if arg.startswith('key='):
            key = arg.replace('key=', '').strip()
        elif arg.startswith('iv='):
            iv = arg.replace('iv=', '').strip()
    if not key:
        raise ValueError("请指定 DES 密钥，例如: key=your_key")
    if not iv:
        raise ValueError("请指定初始化向量，例如: iv=your_iv")
    return key.encode('utf-8'), iv.encode('utf-8')

class DesCbcEncryptInterceptor(BaseInterceptor):
    """DES-CBC 加密拦截器"""
    def __init__(self):
        script_name = os.path.splitext(os.path.basename(__file__))[0]
        self.key, self.iv = get_des_config()
        super().__init__(
            script_name=script_name,
            mode="encrypt",
            processing_fields=get_processing_fields(),
            process_func=self.encrypt_value
        )
    def encrypt_value(self, value: str, url: str, field: str, full_json: Dict[str, Any] = None, form_data: str = "") -> str:
        """
        对指定字段进行 DES-CBC 加密
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
            # 如果不是字符串，先序列化为字符串
            if not isinstance(value, str):
                import json
                value = json.dumps(value, ensure_ascii=False)
            value_bytes = value.encode('utf-8')
            cipher = DES.new(self.key, DES.MODE_CBC, self.iv)
            ciphertext = cipher.encrypt(pad(value_bytes, DES.block_size))
            return base64.b64encode(ciphertext).decode('utf-8')
        except Exception as e:
            self.logger.log(None, f"DES-CBC加密失败: {str(e)}")
            import traceback
            self.logger.log(None, traceback.format_exc())
            return value

# 创建拦截器实例
interceptor = DesCbcEncryptInterceptor()

# 注册插件
addons = [interceptor]
