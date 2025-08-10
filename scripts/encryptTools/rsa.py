"""
RSA 加密脚本-已测试√√√

使用方法:
    mitmdump -p 8888 -s rsa.py --ssl-insecure field=password key=your_public_key
    mitmdump -p 8888 -s rsa.py --ssl-insecure field=password,username key=your_public_key

参数说明:
    field: 需要处理的字段，多个字段用逗号分隔
    key/public_key: RSA 公钥（PEM 格式）

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段加密
    3. 加密结果会进行 Base64 编码
    4. 日志文件保存在 src/logs 目录下，格式为: encrypt_rsa_时间戳.log
"""

import os
import sys
from typing import Dict, Any
import base64
from urllib.parse import unquote
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

# 添加父目录到 Python 路径
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from common.utils import get_processing_fields
from common.interceptor import BaseInterceptor

class RsaEncryptInterceptor(BaseInterceptor):
    """RSA 加密拦截器"""
    def __init__(self):
        script_name = os.path.splitext(os.path.basename(__file__))[0]
        super().__init__(
            script_name=script_name,
            mode="encrypt",
            processing_fields=get_processing_fields(),
            process_func=self.encrypt_value
        )
        self.public_key = self._get_rsa_config()

    def _get_rsa_config(self) -> RSA.RsaKey:
        """获取RSA公钥配置"""
        public_key_path = None
        for arg in sys.argv:
            if arg.startswith('key=') or arg.startswith('public_key='):
                public_key_path = arg.split('=', 1)[1].strip()
        if not public_key_path:
            raise ValueError("必须提供key或public_key参数")
        if not os.path.exists(public_key_path):
            raise ValueError(f"公钥文件不存在: {public_key_path}")
        try:
            with open(public_key_path, 'r') as f:
                return RSA.import_key(f.read())
        except Exception as e:
            raise ValueError(f"读取公钥文件失败: {str(e)}")

    def encrypt_value(self, value: str, url: str, field: str, full_json: Dict[str, Any] = None, form_data: str = "") -> str:
        """
        对指定字段进行 RSA 加密
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
            # 1. 处理表单数据中的空格（将空格替换回+号）
            if form_data:
                value = value.replace(' ', '+')
            # 2. 检查是否需要URL解码
            if '%' in value or '+' in value:
                value = unquote(value)
            # 3. 明文转 bytes
            data = value.encode('utf-8')
            # 4. 公钥加密
            cipher = PKCS1_v1_5.new(self.public_key)
            encrypted = cipher.encrypt(data)
            # 5. Base64 编码
            encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
            
            # 6. URL编码（处理+、/、=等特殊字符）
            from urllib.parse import quote
            encrypted_encoded = quote(encrypted_b64, safe='')
            
            return encrypted_encoded
        except Exception as e:
            self.logger.log(None, f"RSA加密失败: {str(e)}")
            return value

# 创建拦截器实例
interceptor = RsaEncryptInterceptor()

# 注册插件
addons = [interceptor]
