"""
Base64 解密脚本

使用方法:
    mitmdump -p 8888 -s base64.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password
    mitmdump -p 8888 -s base64.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password,username

参数说明:
    -p 8888: 监听端口
    -s base64.py: 指定脚本文件
    --mode upstream:http://127.0.0.1:8080: 指定代理服务器
    --ssl-insecure: 忽略 SSL 证书验证
    field=password: 单个解密字段
    field=password,username: 多个解密字段，用逗号分隔
"""

import sys
from mitmproxy import http
import base64
import logging
import json
from urllib.parse import parse_qs, urlencode

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_decryption_fields():
    """
    从命令行参数获取解密配置
    
    Returns:
        list: 需要解密的字段名称列表
    """
    all_args = sys.argv
    decryption_fields = []

    # 遍历所有参数
    for arg in all_args:
        if arg.startswith('field='):
            # 提取 field= 后面的值
            fields = arg.replace('field=', '')
            decryption_fields = [field.strip() for field in fields.split(',') if field.strip()]
            break

    if not decryption_fields:
        decryption_fields = ['password']  # 默认解密字段

    logging.info(f"需要解密的字段: {decryption_fields}")
    return decryption_fields

class Base64DecodeInterceptor:
    def __init__(self, decryption_fields):
        self.decryption_fields = decryption_fields
        logging.info("成功初始化Base64解密器")

    def decode_value(self, encoded_text: str) -> str:
        """Base64解码"""
        try:
            decoded_bytes = base64.b64decode(encoded_text)
            return decoded_bytes.decode('utf-8')
        except Exception as e:
            logging.error(f"解码失败: {e}")
            return encoded_text

    def process_json_data(self, json_data: dict) -> tuple[dict, bool]:
        """处理JSON数据"""
        modified = False
        for field in self.decryption_fields:
            if field in json_data:
                try:
                    encoded_value = json_data[field]
                    logging.info(f"JSON字段 {field} 待解码值: {encoded_value}")
                    decoded_value = self.decode_value(encoded_value)
                    
                    try:
                        json_data[field] = json.loads(decoded_value)
                    except json.JSONDecodeError:
                        json_data[field] = decoded_value
                    
                    modified = True
                    logging.info(f"JSON字段 {field} 解码完成")
                except Exception as e:
                    logging.error(f"解码字段 {field} 失败: {e}")
        return json_data, modified

    def process_form_data(self, form_data: str) -> tuple[str, bool]:
        """处理表单数据"""
        params = parse_qs(form_data, keep_blank_values=True)
        modified = False

        for field in self.decryption_fields:
            if field in params:
                try:
                    values = params[field]
                    if isinstance(values, list):
                        decoded_values = []
                        for value in values:
                            logging.info(f"表单字段 {field} 待解码值: {value}")
                            decoded_values.append(self.decode_value(value))
                        params[field] = decoded_values
                    else:
                        logging.info(f"表单字段 {field} 待解码值: {values}")
                        params[field] = self.decode_value(values)
                    modified = True
                    logging.info(f"表单字段 {field} 解码完成")
                except Exception as e:
                    logging.error(f"解码字段 {field} 失败: {e}")

        for key in params:
            if isinstance(params[key], list) and len(params[key]) == 1:
                params[key] = params[key][0]

        return urlencode(params), modified

    def request(self, flow: http.HTTPFlow) -> None:
        """处理请求"""
        try:
            content_type = flow.request.headers.get("Content-Type", "")
            logging.info("=" * 50)
            logging.info(f"原始请求数据包:\n{flow.request.method} {flow.request.pretty_url}")
            logging.info(f"Content-Type: {content_type}")
            logging.info(f"{flow.request.content.decode('utf-8')}")

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
                logging.info("\n解码后的请求数据包:")
                logging.info(f"{flow.request.content.decode('utf-8')}")

            logging.info("=" * 50)

        except Exception as e:
            logging.error(f"处理请求失败: {e}")
            import traceback
            logging.error(traceback.format_exc())

# 获取解密配置
decryption_fields = get_decryption_fields()

# 注册插件
addons = [Base64DecodeInterceptor(decryption_fields)] 