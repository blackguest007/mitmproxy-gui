"""
Base64 加密脚本-已测试√

使用方法:
    mitmdump -p 8888 -s Base64.py --ssl-insecure field=password
    mitmdump -p 8888 -s Base64.py --ssl-insecure field=password,username

参数说明:
    field: 需要处理的字段，多个字段用逗号分隔

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段处理
    3. Base64加密结果为标准Base64编码字符串
    4. 日志文件保存在 src/logs 目录下，格式为: encrypt_base64_时间戳.log
"""
import json
import os
import sys

from scripts.common.interceptor import BaseInterceptor
from scripts.common.utils import get_processing_fields

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

import base64
from typing import Dict, Any


class Base64EncryptInterceptor(BaseInterceptor):
    """Base64 加密拦截器"""
    def __init__(self):
        script_name = os.path.splitext(os.path.basename(__file__))[0]
        super().__init__(
            script_name=script_name,
            mode="encrypt",
            processing_fields=get_processing_fields(),
            process_func=self.encrypt_value
        )

    def encrypt_value(self, value: str, url: str, field: str, full_json: Dict[str, Any] = None, form_data: str = "") -> str:
        """
        对指定字段进行 Base64 编码
        Args:
            value: 要加密的值
            url: 请求 URL
            field: 字段名
            full_json: 完整的 JSON 数据（如果是 JSON 请求）
            form_data: 完整的表单数据（如果是表单请求）
        Returns:
            str: Base64 编码后的值
        """

def encrypt_value(self, value: str, url: str, field: str, full_json: Dict[str, Any] = None, form_data: str = "") -> str:
    try:
        if not isinstance(value, str):
            value = json.dumps(value, ensure_ascii=False)
        self.logger.log(url, f"Base64加密前的值: {value}")  # 主动记录加密前
        encoded = base64.b64encode(value.encode('utf-8')).decode('utf-8')
        self.logger.log(url, f"Base64加密后: {encoded}")  # 主动记录加密后
        return encoded
    except Exception as e:
        self.logger.log(None, f"Base64加密失败: {str(e)}")
        return value

# 创建拦截器实例
interceptor = Base64EncryptInterceptor()

# 注册插件
addons = [interceptor]