"""
MD5 加密脚本

使用方法:
    mitmdump -p 8888 -s md5.py --ssl-insecure password
    mitmdump -p 8888 -s md5.py --ssl-insecure password,username,token

参数说明:
    -p 8888: 监听端口
    -s md5.py: 指定脚本文件
    --ssl-insecure: 忽略 SSL 证书验证
    password: 单个加密字段
    password,username,token: 多个加密字段，用逗号分隔

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段加密
    3. MD5加密结果为32位小写字符串
"""

import sys
import os
from mitmproxy import http
import hashlib
import logging
import json
from urllib.parse import parse_qs, urlencode

# 修改导入路径的设置
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))
sys.path.insert(0, project_root)


# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_encryption_fields():
    """从命令行参数获取加密配置"""
    all_args = sys.argv
    encryption_fields = []

    for arg in all_args:
        if not arg.startswith('-'):
            if 'field=' in arg:
                fields = arg.split('=', 1)[1].strip().split(',')
                encryption_fields.extend([field.strip() for field in fields if field.strip()])
            else:
                try:
                    float(arg)
                except ValueError:
                    continue

    if not encryption_fields:
        encryption_fields = ['password']  # 默认加密字段

    logging.info(f"需要加密的字段: {encryption_fields}")
    return encryption_fields

encryption_fields = get_encryption_fields()

class MD5EncryptInterceptor:
    """MD5 加密拦截器"""
    
    def __init__(self, field_names):
        """
        初始化加密器
        
        Args:
            field_names (list): 需要加密的字段名称列表
        """
        self.field_names = field_names
        logging.info(f"加密目标字段: {self.field_names}")

    def process_json_data(self, json_data: dict) -> tuple[dict, bool]:
        """处理JSON数据"""
        modified = False
        for field in self.field_names:
            if field in json_data:
                try:
                    # 将字段值转换为标准 JSON 字符串（使用双引号）
                    if isinstance(json_data[field], (dict, list)):
                        plain_text = json.dumps(json_data[field], ensure_ascii=False)
                    else:
                        plain_text = str(json_data[field])
                    
                    logging.info(f"JSON字段 {field} 待加密值: {plain_text}")
                    json_data[field] = self.encrypt_value(plain_text)
                    modified = True
                    logging.info(f"JSON字段 {field} 加密完成")
                except Exception as e:
                    logging.error(f"加密字段 {field} 失败: {e}")
        return json_data, modified

    def process_form_data(self, form_data: str) -> tuple[str, bool]:
        """处理表单数据"""
        params = parse_qs(form_data, keep_blank_values=True)
        modified = False

        for field in self.field_names:
            if field in params:
                try:
                    values = params[field]
                    if isinstance(values, list):
                        encrypted_values = []
                        for value in values:
                            logging.info(f"表单字段 {field} 待加密值: {value}")
                            md5_hash = hashlib.md5()
                            md5_hash.update(value.encode('utf-8'))
                            encrypted_values.append(md5_hash.hexdigest())
                        params[field] = encrypted_values
                    else:
                        logging.info(f"表单字段 {field} 待加密值: {values}")
                        md5_hash = hashlib.md5()
                        md5_hash.update(values.encode('utf-8'))
                        params[field] = md5_hash.hexdigest()
                    modified = True
                    logging.info(f"表单字段 {field} 加密完成")
                except Exception as e:
                    logging.error(f"加密字段 {field} 失败: {e}")

        for key in params:
            if isinstance(params[key], list) and len(params[key]) == 1:
                params[key] = params[key][0]

        return urlencode(params), modified

    def request(self, flow: http.HTTPFlow) -> None:
        """
        处理请求
        
        Args:
            flow: mitmproxy的请求流对象
        """
        try:
            content_type = flow.request.headers.get("Content-Type", "")
            logging.info("=" * 50)
            logging.info(f"请求URL: {flow.request.pretty_url}")
            logging.info(f"请求方法: {flow.request.method}")
            logging.info(f"Content-Type: {content_type}")

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
                logging.info(f"加密后的请求数据: {flow.request.content.decode('utf-8')}")

            logging.info("=" * 50)

        except Exception as e:
            logging.error(f"处理请求失败: {e}")
            import traceback
            logging.error(traceback.format_exc())

# 注册插件
addons = [MD5EncryptInterceptor(encryption_fields)]
