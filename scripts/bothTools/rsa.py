"""
RSA 双向加解密脚本 (v1.0.5重构版) - 已测试√√√

【架构说明】
基于 BothInterceptor 统一架构，实现真正的双向代理：
- 请求流：客户端 → [解密] → 上游服务器
- 响应流：上游服务器 → [加密] → 客户端

【使用方法】
完整模式: mitmdump -p 8888 -s rsa.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password public_key=path/to/public_key.pem private_key=path/to/private_key.pem
仅解密:   mitmdump -p 8888 -s rsa.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password private_key=path/to/private_key.pem
仅加密:   mitmdump -p 9999 -s rsa.py --ssl-insecure field=password public_key=path/to/public_key.pem

【参数说明】
field:       需要处理的字段，多个字段用逗号分隔
public_key:  RSA公钥文件路径（PEM格式，用于加密响应）
private_key: RSA私钥文件路径（PEM格式，用于解密请求）
key:         通用密钥参数（根据模式自动判断是公钥还是私钥）

【功能特性】
1. 支持 application/json 和 application/x-www-form-urlencoded 格式
2. 支持单个或多个字段同时处理
3. 双向模式：请求自动解密，响应自动加密
4. 统一 process_value 接口，通过 is_response 参数区分处理方向
5. 独立的请求/响应日志记录
6. 密钥文件必须是PEM格式
7. 缺少密钥时跳过对应操作并记录日志
"""

import os
import sys
import base64
from typing import Dict, Any
from urllib.parse import unquote
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

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

def get_rsa_config():
    """获取RSA配置"""
    public_key_path = None
    private_key_path = None
    
    # 参考加密/解密模式的参数处理方式
    for arg in sys.argv:
        if arg.startswith('public_key='):
            public_key_path = arg.split('=', 1)[1].strip()
        elif arg.startswith('private_key='):
            private_key_path = arg.split('=', 1)[1].strip()
        elif arg.startswith('key='):  # 兼容单个key参数
            key_path = arg.split('=', 1)[1].strip()
            # 根据运行模式决定是公钥还是私钥
            mode = get_mode()
            if mode == 'decrypt':
                private_key_path = key_path
            else:
                public_key_path = key_path
    
    # 检查运行模式，决定需要哪些密钥
    mode = get_mode()
    public_key = None
    private_key = None
    
    # 根据模式和响应需要，可能需要两个密钥
    # both模式需要两个密钥：解密请求用私钥，加密响应用公钥
    if not public_key_path and not private_key_path:
        raise ValueError("必须提供public_key或private_key参数")
    
    try:
        # 读取公钥（如果提供）
        if public_key_path:
            if not os.path.exists(public_key_path):
                raise ValueError(f"公钥文件不存在: {public_key_path}")
            with open(public_key_path, 'r') as f:
                public_key = f.read()
            RSA.import_key(public_key)  # 验证格式
        
        # 读取私钥（如果提供）
        if private_key_path:
            if not os.path.exists(private_key_path):
                raise ValueError(f"私钥文件不存在: {private_key_path}")
            with open(private_key_path, 'r') as f:
                private_key = f.read()
            RSA.import_key(private_key)  # 验证格式
        
        return public_key, private_key
    except Exception as e:
        raise ValueError(f"读取或验证密钥文件失败: {str(e)}")

class RsaBothInterceptor(BothInterceptor):
    """RSA 双向加解密拦截器"""
    
    def __init__(self):
        script_name = os.path.splitext(os.path.basename(__file__))[0]
        self.public_key, self.private_key = get_rsa_config()
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
            
            if current_mode == 'decrypt':
                # 解密逻辑（使用私钥）- 参考decryptTools/rsa.py的完整实现
                if not value or not value.strip():
                    return value
                if not self.private_key:
                    self.logger.log(None, f"解密失败: 缺少私钥")
                    return value
                
                try:
                    # 1. 处理表单数据中的空格（将空格替换回+号）
                    processed_value = value.replace(' ', '+')
                    
                    # 2. 检查是否需要URL解码
                    if '%' in processed_value or '+' in processed_value:
                        processed_value = unquote(processed_value)
                    
                    # 3. 检查是否是有效的Base64编码
                    from common.utils import is_valid_base64
                    if not is_valid_base64(processed_value):
                        self.logger.log(None, f"无效的Base64编码: {processed_value}")
                        return value
                    
                    # 4. Base64解码
                    try:
                        encrypted_data = base64.b64decode(processed_value)
                    except Exception as e:
                        self.logger.log(None, f"Base64解码错误: {str(e)}")
                        return value
                    
                    # 5. RSA解密
                    try:
                        key = RSA.import_key(self.private_key)
                        cipher = PKCS1_v1_5.new(key)
                        decrypted_data = cipher.decrypt(encrypted_data, None)
                        
                        if decrypted_data is None:
                            self.logger.log(None, "RSA解密返回None")
                            return value
                        
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
            else:
                # 加密逻辑（使用公钥）- 参考encryptTools/rsa.py的完整实现
                if not self.public_key:
                    self.logger.log(None, f"加密失败: 缺少公钥")
                    return value
                
                try:
                    # 1. 处理表单数据中的空格
                    processed_value = value.replace(' ', '+')
                    
                    # 2. 检查是否需要URL解码
                    if '%' in processed_value or '+' in processed_value:
                        processed_value = unquote(processed_value)
                    
                    # 3. 去除引号
                    processed_value = processed_value.strip('"').strip("'")
                    
                    # 4. 明文转 bytes
                    data = processed_value.encode('utf-8')
                    
                    # 5. 公钥加密
                    key = RSA.import_key(self.public_key)
                    cipher = PKCS1_v1_5.new(key)
                    encrypted = cipher.encrypt(data)
                    
                    # 6. Base64 编码
                    encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
                    
                    # 7. URL编码（处理+、/、=等特殊字符）
                    from urllib.parse import quote
                    encrypted_encoded = quote(encrypted_b64, safe='')
                    
                    return encrypted_encoded
                    
                except Exception as e:
                    self.logger.log(None, f"RSA加密失败: {str(e)}")
                    return value
                    
        except Exception as e:
            self.logger.log(None, f"处理失败: {str(e)}")
            return value

# 创建拦截器实例
interceptor = RsaBothInterceptor()

# 注册插件
addons = [interceptor]