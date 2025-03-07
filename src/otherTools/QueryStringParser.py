# path: src/otherTools/QueryStringParser.py

import re


class QueryStringParser:
    def __init__(self, query_string: str):
        self.query_string = query_string

    # 将请求参数解析成为字典形式
    def parse_request_params(self):
        """使用正则表达式解析查询字符串"""
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
