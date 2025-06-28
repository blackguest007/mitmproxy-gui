"""
RSA 解密脚本-已测试√

使用方法:
    mitmdump -p 8888 -s rsa.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password key=your_private_key

参数说明:
    field: 需要处理的字段，多个字段用逗号分隔
    key: RSA私钥，PEM格式

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段处理
    3. 私钥必须是PEM格式
    4. 解密前的数据需要是Base64编码
"""

import os
import sys
from typing import Dict, Any, Tuple
from mitmproxy import http
import base64
from urllib.parse import unquote
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

# 添加父目录到 Python 路径
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from scripts.common.interceptor import BaseInterceptor
from scripts.common.utils import get_processing_fields, is_valid_base64

class RsaDecryptInterceptor(BaseInterceptor):
    """RSA 解密拦截器"""
    
    def __init__(self):
        """初始化RSA解密拦截器"""
        script_name = os.path.splitext(os.path.basename(__file__))[0]
        super().__init__(
            script_name=script_name,
            mode="decrypt",
            processing_fields=get_processing_fields(),
            process_func=self.decrypt_value
        )
        
        # 获取RSA配置
        self.private_key = self._get_rsa_config()

    def _get_rsa_config(self) -> RSA.RsaKey:
        """获取RSA配置"""
        private_key_path = None
        for arg in sys.argv:
            if arg.startswith('key=') or arg.startswith('private_key='):
                private_key_path = arg.split('=', 1)[1].strip()
        
        if not private_key_path:
            raise ValueError("必须提供key或private_key参数")
        if not os.path.exists(private_key_path):
            raise ValueError(f"私钥文件不存在: {private_key_path}")
            
        try:
            with open(private_key_path, 'r') as f:
                return RSA.import_key(f.read())
        except Exception as e:
            raise ValueError(f"读取私钥文件失败: {str(e)}")

    def decrypt_value(self, value: str, url: str, field: str, full_json: Dict[str, Any] = None, form_data: str = "") -> str:
        """
        解密RSA加密的值
        
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
            
            # 5. RSA解密
            try:
                cipher = PKCS1_v1_5.new(self.private_key)
                decrypted_data = cipher.decrypt(encrypted_data, None)
                
                # 尝试不同的字符集解码
                charsets = ['utf-8', 'gbk', 'gb2312', 'latin1']
                decrypted_text = None
                
                for charset in charsets:
                    try:
                        decrypted_text = decrypted_data.decode(charset)
                        break
                    except UnicodeDecodeError:
                        continue
                
                if decrypted_text is None:
                    self.logger.log(None, "无法使用支持的字符集解码解密结果")
                    return value
                
                if not decrypted_text:
                    self.logger.log(None, "解密结果为空字符串")
                    return value
                
                return decrypted_text
            except Exception as e:
                self.logger.log(None, f"RSA解密错误: {str(e)}")
                return value
                
        except Exception as e:
            self.logger.log(None, f"解密过程错误: {str(e)}")
            return value

# 创建拦截器实例
interceptor = RsaDecryptInterceptor()

# 注册插件
addons = [interceptor]