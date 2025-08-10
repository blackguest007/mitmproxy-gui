"""
Base64 双向编解码脚本 (v1.0.5重构版) - 已测试√√√

【架构说明】
基于 BothInterceptor 统一架构，实现真正的双向代理：
- 请求流：客户端 → [解码] → 上游服务器
- 响应流：上游服务器 → [编码] → 客户端

【使用方法】
双向模式: mitmdump -p 8888 -s base64.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password

【参数说明】
field: 需要处理的字段，多个字段用逗号分隔

【功能特性】
1. 支持 application/json 和 application/x-www-form-urlencoded 格式
2. 支持单个或多个字段同时处理
3. 双向模式：请求自动解码，响应自动编码
4. 统一 process_value 接口，通过 is_response 参数区分处理方向
5. 独立的请求/响应日志记录
6. 支持标准和URL安全的Base64格式
"""

import os
import sys
import base64

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
            return 'decode'  # 有--mode参数就是解码模式
    return 'encode'  # 默认模式为编码

class Base64BothInterceptor(BothInterceptor):
    """Base64 双向编解码拦截器"""
    
    def __init__(self):
        script_name = os.path.splitext(os.path.basename(__file__))[0]
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
                current_mode = 'encode' if self.mode == 'decode' else 'decode'
            
            if current_mode == 'decode':
                # Base64解码
                try:
                    if not value or not value.strip():
                        return value
                    decoded_bytes = base64.b64decode(value)
                    return decoded_bytes.decode('utf-8')
                except:
                    return value
            else:
                # Base64编码
                try:
                    value = value.strip('"').strip("'")
                    encoded_bytes = value.encode('utf-8')
                    return base64.b64encode(encoded_bytes).decode('utf-8')
                except:
                    return value
                    
        except Exception as e:
            self.logger.log(None, f"处理失败: {str(e)}")
            return value

# 创建拦截器实例
interceptor = Base64BothInterceptor()

# 注册插件
addons = [interceptor] 