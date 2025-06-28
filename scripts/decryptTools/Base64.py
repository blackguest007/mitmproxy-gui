@ -1,97 +0,0 @@
"""
Base64 解密脚本-已测试√

使用方法:
    mitmdump -p 8888 -s Base64.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=data

参数说明:
    field: 需要处理的字段，多个字段用逗号分隔

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段处理
    3. 解密前的数据需要是Base64编码
"""

import os
import sys
from typing import Dict, Any
from mitmproxy import http
import base64
from urllib.parse import unquote

# 添加父目录到 Python 路径
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from common.utils import get_processing_fields, is_valid_base64
from common.interceptor import BaseInterceptor

class Base64DecryptInterceptor(BaseInterceptor):
    """Base64 解密拦截器"""
    
    def __init__(self):
        """初始化Base64解密拦截器"""
        script_name = os.path.splitext(os.path.basename(__file__))[0]
        super().__init__(
            script_name=script_name,
            mode="decrypt",
            processing_fields=get_processing_fields(),
            process_func=self.decrypt_value
        )

    def decrypt_value(self, value: str, url: str, field: str, full_json: Dict[str, Any] = None, form_data: str = "") -> str:
        """
        解密Base64编码的值
        
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
            # 1. 检查是否需要URL解码
            if '%' in value or '+' in value:
                value = unquote(value)
            
            # 2. 检查是否是有效的Base64编码
            if not is_valid_base64(value):
                self.logger.log(None, f"无效的Base64编码: {value}")
                return value
                
            # 3. Base64解码
            try:
                decoded_data = base64.b64decode(value)
            except Exception as e:
                self.logger.log(None, f"Base64解码错误: {str(e)}")
                return value
            
            # 4. UTF-8解码
            try:
                decoded_text = decoded_data.decode('utf-8')
                
                if not decoded_text:
                    self.logger.log(None, "解码结果为空字符串")
                    return value
                
                return decoded_text
            except Exception as e:
                self.logger.log(None, f"UTF-8解码错误: {str(e)}")
                return value
                
        except Exception as e:
            self.logger.log(None, f"解码过程错误: {str(e)}")
            return value

# 创建拦截器实例
interceptor = Base64DecryptInterceptor()

# 注册插件
addons = [interceptor] 