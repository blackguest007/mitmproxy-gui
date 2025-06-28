"""
<<<<<<< HEAD
AES-CBC 解密脚本-已测试√√√
=======
AES-CBC 解密脚本√
>>>>>>> 003e959c53f0a3ebe65ba51c3c236e85da3c6263

使用方法:
    mitmdump -p 8888 -s aes_cbc.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password key=your_key iv=your_iv

参数说明:
    field: 需要处理的字段，多个字段用逗号分隔
    key: AES密钥，长度必须为16、24或32字节
    iv: 初始化向量，长度必须为16字节

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段处理
    3. 密钥长度必须符合要求
    4. 解密前的数据需要是Base64编码
"""

import os
import sys
from typing import Dict, Any, Tuple
from mitmproxy import http
import base64
from urllib.parse import unquote
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 添加父目录到 Python 路径
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

<<<<<<< HEAD
from common.utils import get_processing_fields, is_valid_base64
from common.interceptor import BaseInterceptor
=======
from scripts.common.interceptor import BaseInterceptor
from scripts.common.utils import get_processing_fields, is_valid_base64
>>>>>>> 003e959c53f0a3ebe65ba51c3c236e85da3c6263

class AesCbcDecryptInterceptor(BaseInterceptor):
    """AES-CBC 解密拦截器"""
    
    def __init__(self):
        """初始化AES-CBC解密拦截器"""
        script_name = os.path.splitext(os.path.basename(__file__))[0]
        super().__init__(
            script_name=script_name,
            mode="decrypt",
            processing_fields=get_processing_fields(),
            process_func=self.decrypt_value
        )
        
        # 获取AES配置
        self.key, self.iv = self._get_aes_config()

    def _get_aes_config(self) -> Tuple[bytes, bytes]:
        """获取AES配置"""
        key = None
        iv = None
        for arg in sys.argv:
            if arg.startswith('key='):
                key = arg.replace('key=', '').strip()
            elif arg.startswith('iv='):
                iv = arg.replace('iv=', '').strip()
        
        if not key:
            raise ValueError("必须提供key参数")
        if not iv:
            raise ValueError("必须提供iv参数")
        
        # 直接转换为字节
        key_bytes = key.encode('utf-8')
        iv_bytes = iv.encode('utf-8')
        
        # 验证密钥长度（支持AES-128/192/256）
        if len(key_bytes) not in [16, 24, 32]:
            raise ValueError(f"无效的AES密钥长度: {len(key_bytes)}字节，应为16/24/32字节")
        
        # 验证IV长度（支持16字节，兼容其他长度）
        if len(iv_bytes) != 16:
            raise ValueError(f"无效的IV长度: {len(iv_bytes)}字节，应为16字节")
        
        return key_bytes, iv_bytes

    def decrypt_value(self, value: str, url: str, field: str, full_json: Dict[str, Any] = None, form_data: str = "") -> str:
        """
        解密AES-CBC加密的值
        
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
            
            # 5. AES解密
            try:
                cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
                decrypted_padded = cipher.decrypt(encrypted_data)
                
                # 检查是否需要去填充
                try:
                    decrypted_data = unpad(decrypted_padded, AES.block_size)
                except ValueError:
                    # 如果去填充失败，说明数据可能没有填充，直接使用解密后的数据
                    decrypted_data = decrypted_padded
                    
            except Exception as e:
                self.logger.log(None, f"AES解密错误: {str(e)}")
                return value
            
            # 6. UTF-8解码
            try:
                decrypted_text = decrypted_data.decode('utf-8')
                
                if not decrypted_text:
                    self.logger.log(None, "解密结果为空字符串")
                    return value
                
                return decrypted_text
            except Exception as e:
                self.logger.log(None, f"UTF-8解码错误: {str(e)}")
                return value
                
        except Exception as e:
            self.logger.log(None, f"解密过程错误: {str(e)}")
            return value

# 创建拦截器实例
interceptor = AesCbcDecryptInterceptor()

# 注册插件
addons = [interceptor] 