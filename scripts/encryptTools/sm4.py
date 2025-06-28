"""
SM4 加密脚本

使用方法:
    mitmdump -p 8888 -s sm4.py --ssl-insecure field=password key=your_key
    mitmdump -p 8888 -s sm4.py --ssl-insecure field=password,username key=your_key

参数说明:
    -p 8888: 监听端口
    -s sm4.py: 指定脚本文件
    --ssl-insecure: 忽略 SSL 证书验证
    field=password: 单个加密字段
    field=password,username: 多个加密字段，用逗号分隔
    key=your_key: SM4 密钥（16字节）

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段加密
    3. 加密结果会进行 Base64 编码
    4. 日志文件保存在 logs 目录下，格式为: encrypt_sm4_时间戳.log
"""

import sys
import os
import base64
from typing import Dict, Any, List
from gmssl import sm4, func

# 添加父目录到系统路径
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from common.interceptor import BaseInterceptor

def get_encryption_config() -> Dict[str, Any]:
    """从命令行参数获取加密配置"""
    config = {
        'fields': [],
        'key': None
    }
    
    for arg in sys.argv:
        if arg.startswith('field='):
            config['fields'] = [field.strip() for field in arg.replace('field=', '').split(',') if field.strip()]
        elif arg.startswith('key='):
            config['key'] = arg.replace('key=', '').strip()
            
    return config

class Sm4EncryptInterceptor(BaseInterceptor):
    """SM4 加密拦截器"""
    
    def __init__(self):
        """初始化拦截器"""
        config = get_encryption_config()
        if not config['fields']:
            raise ValueError("请指定要加密的字段，例如: field=password")
        if not config['key']:
            raise ValueError("请指定 SM4 密钥，例如: key=your_key")
            
        try:
            # 创建 SM4 加密器
            self.crypt_sm4 = sm4.CryptSM4()
            # 设置密钥
            self.crypt_sm4.set_key(config['key'].encode('utf-8'), sm4.SM4_ENCRYPT)
        except Exception as e:
            raise ValueError(f"无效的 SM4 密钥: {str(e)}")
        
        super().__init__(
            script_name="sm4",
            mode="encrypt",
            processing_fields=config['fields'],
            process_func=self.encrypt_value
        )
        
    def encrypt_value(self, value: str, url: str, field: str, full_json: Dict[str, Any] = None, form_data: str = "") -> str:
        """
        对指定字段进行 SM4 加密
        
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
            # 移除可能的引号
            value = value.strip('"').strip("'")
            # 加密数据
            ciphertext = self.crypt_sm4.crypt_ecb(value.encode('utf-8'))
            # Base64 编码
            return base64.b64encode(ciphertext).decode('utf-8')
        except Exception as e:
            self.logger.log(None, f"SM4加密失败: {str(e)}")
            return value

# 创建拦截器实例
interceptor = Sm4EncryptInterceptor()

# 注册请求和响应处理函数
def request(flow):
    interceptor.request(flow)

def response(flow):
    interceptor.response(flow)

def done():
    interceptor.done() 