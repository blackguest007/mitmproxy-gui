"""
Query string parser module.
Provides functionality for parsing URL query strings.
"""

import re
from typing import Dict, List


class QueryStringParser:
    """URL查询字符串解析器"""

    def __init__(self, query_string: str):
        """初始化解析器

        Args:
            query_string: 要解析的查询字符串
        """
        self.query_string = query_string

    def parse_request_params(self) -> Dict[str, List[str]]:
        """使用正则表达式解析查询字符串

        Returns:
            Dict[str, List[str]]: 解析后的参数字典，每个参数值都是一个列表
        """
        params = {}
        # 使用正则解析查询参数（包括空值的参数）
        pattern = re.compile(r'([^&=]+)=?([^&]*)')
        for match in pattern.finditer(self.query_string):
            key = match.group(1)
            value = match.group(2) or ''  # 如果没有值，设置为空字符串
            if key in params:
                params[key].append(value)
            else:
                params[key] = [value]
        return params 