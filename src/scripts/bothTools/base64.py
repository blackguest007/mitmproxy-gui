"""
Base64 双向加解密脚本

使用方法:
    加密: mitmdump -p 9999 -s base64.py --ssl-insecure field=password
    解密: mitmdump -p 8888 -s base64.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password

参数说明:
    field=password: 需要处理的字段，多个字段用逗号分隔
    
注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段处理
    3. 自动检测运行模式（加密/解密）
"""

import sys
from mitmproxy import http
import base64
import logging
import json
from urllib.parse import parse_qs, urlencode

# 配置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_fields():
    """获取需要处理的字段"""
    all_args = sys.argv
    fields = []
    
    for arg in all_args:
        if arg.startswith('field='):
            fields = [field.strip() for field in arg.replace('field=', '').split(',') if field.strip()]
            break
    
    if not fields:
        fields = ['password']  # 默认字段
        
    logging.info(f"需要处理的字段: {fields}")
    return fields

def is_encrypt_mode():
    """判断是加密还是解密模式"""
    return '--mode' not in ' '.join(sys.argv)

class Base64Processor:
    def __init__(self, fields):
        self.fields = fields
        self.is_encrypt = is_encrypt_mode()
        mode = "加密" if self.is_encrypt else "解密"
        logging.info(f"初始化 Base64 {mode}处理器")
    
    def process_value(self, value: str) -> str:
        """处理单个值"""
        try:
            if self.is_encrypt:
                return base64.b64encode(value.encode('utf-8')).decode('utf-8')
            else:
                return base64.b64decode(value).decode('utf-8')
        except Exception as e:
            logging.error(f"处理失败: {e}")
            return value

    def process_json_data(self, json_data: dict) -> tuple[dict, bool]:
        """处理JSON数据"""
        modified = False
        for field in self.fields:
            if field in json_data:
                try:
                    value = str(json_data[field])
                    mode = "加密" if self.is_encrypt else "解密"
                    logging.info(f"JSON字段 {field} 待{mode}值: {value}")
                    json_data[field] = self.process_value(value)
                    modified = True
                    logging.info(f"JSON字段 {field} {mode}完成")
                except Exception as e:
                    logging.error(f"处理字段 {field} 失败: {e}")
        return json_data, modified

    def process_form_data(self, form_data: str) -> tuple[str, bool]:
        """处理表单数据"""
        params = parse_qs(form_data, keep_blank_values=True)
        modified = False
        
        for field in self.fields:
            if field in params:
                try:
                    values = params[field]
                    mode = "加密" if self.is_encrypt else "解密"
                    if isinstance(values, list):
                        processed_values = []
                        for value in values:
                            logging.info(f"表单字段 {field} 待{mode}值: {value}")
                            processed_values.append(self.process_value(value))
                        params[field] = processed_values
                    else:
                        logging.info(f"表单字段 {field} 待{mode}值: {values}")
                        params[field] = self.process_value(values)
                    modified = True
                    logging.info(f"表单字段 {field} {mode}完成")
                except Exception as e:
                    logging.error(f"处理字段 {field} 失败: {e}")

        for key in params:
            if isinstance(params[key], list) and len(params[key]) == 1:
                params[key] = params[key][0]

        return urlencode(params), modified

    def request(self, flow: http.HTTPFlow) -> None:
        """处理请求"""
        try:
            content_type = flow.request.headers.get("Content-Type", "")
            mode = "加密" if self.is_encrypt else "解密"
            logging.info("=" * 50)
            logging.info(f"请求URL: {flow.request.pretty_url}")
            logging.info(f"请求方法: {flow.request.method}")
            logging.info(f"Content-Type: {content_type}")
            logging.info(f"运行模式: {mode}")

            modified = False
            if "application/json" in content_type:
                json_data = json.loads(flow.request.content)
                json_data, modified = self.process_json_data(json_data)
                if modified:
                    new_content = json.dumps(json_data, separators=(',', ':'))
                    flow.request.content = new_content.encode('utf-8')

            elif "application/x-www-form-urlencoded" in content_type:
                form_data = flow.request.content.decode('utf-8')
                new_content, modified = self.process_form_data(form_data)
                if modified:
                    flow.request.content = new_content.encode('utf-8')

            if modified:
                flow.request.headers["Content-Length"] = str(len(flow.request.content))
                logging.info(f"{mode}后的请求数据: {flow.request.content.decode('utf-8')}")

            logging.info("=" * 50)

        except Exception as e:
            logging.error(f"处理请求失败: {e}")
            import traceback
            logging.error(traceback.format_exc())

# 获取配置并注册插件
fields = get_fields()
addons = [Base64Processor(fields)] 