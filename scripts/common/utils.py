"""
公共工具函数模块

提供以下功能：
1. 命令行参数处理
2. Base64 格式验证
3. 其他通用工具函数
"""

import sys
import base64
from typing import List

def get_processing_fields() -> List[str]:
    """
    从命令行参数获取处理字段配置
    
    Returns:
        list: 需要处理的字段名称列表
    """
    all_args = sys.argv
    processing_fields = []

    # 遍历所有参数
    for arg in all_args:
        if arg.startswith('field='):
            # 提取 field= 后面的值
            fields = arg.replace('field=', '')
            processing_fields = [field.strip() for field in fields.split(',') if field.strip()]
            break

    if not processing_fields:
        processing_fields = ['password']  # 默认处理字段

    return processing_fields

def is_valid_base64(s: str) -> bool:
    """
    检查字符串是否是有效的Base64编码
    
    Args:
        s: 要检查的字符串
        
    Returns:
        bool: 是否是有效的Base64编码
    """
    try:
        # 检查字符串长度是否为4的倍数
        if len(s) % 4 != 0:
            return False
        # 检查是否只包含Base64字符
        if not all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in s):
            return False
        # 尝试解码
        base64.b64decode(s)
        return True
    except Exception:
        return False 