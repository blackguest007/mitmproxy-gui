"""
3DES-CBC 加密脚本

使用方法:
    mitmdump -p 8888 -s des3_cbc.py --ssl-insecure field=data key=123456789012345678901234 iv=12345678

参数说明:
    -p 8888: 监听端口
    -s des3_cbc.py: 指定脚本文件
    --ssl-insecure: 忽略 SSL 证书验证
    field: 需要加密的字段名称，多个字段用逗号分隔
    key: 3DES密钥，必须是16字节(128位)或24字节(192位)
    iv: 初始化向量，必须是8字节长度

注意事项:
    1. 3DES密钥必须是16字节或24字节长度
    2. 支持 application/json 和 application/x-www-form-urlencoded 格式
    3. 加密结果使用 Base64 编码
"""

import sys
from mitmproxy import http
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad
import base64
import logging
import json
from urllib.parse import parse_qs, urlencode
import traceback

# 配置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_encryption_fields():
    """从命令行参数获取加密配置"""
    all_args = sys.argv
    encryption_fields = []
    key = None
    iv = None

    for arg in all_args:
        if not arg.startswith('-'):
            if 'key=' in arg:
                key = arg.split('=')[1]
            elif 'iv=' in arg:
                iv = arg.split('=')[1]
            elif 'field=' in arg:
                fields = arg.split('=', 1)[1].strip().split(',')
                encryption_fields.extend([field.strip() for field in fields if field.strip()])
            else:
                try:
                    float(arg)
                except ValueError:
                    continue

    if not encryption_fields:
        encryption_fields = ['data']

    logging.info(f"需要加密的字段: {encryption_fields}")
    return encryption_fields, key, iv


# 获取加密配置
encryption_fields, key, iv = get_encryption_fields()


class Des3EncryptInterceptor:
    """3DES-CBC 加密拦截器"""

    def __init__(self, encryption_fields, key, iv):
        self.encryption_fields = encryption_fields
        self.key = key.encode('utf-8')
        self.iv = iv.encode('utf-8')
        logging.info("成功初始化3DES-CBC加密器")

    def encrypt_value(self, plain_text: str) -> str:
        """加密单个值"""
        try:
            # 使用与 CryptoJS.TripleDES 相同的加密方式
            cipher = DES3.new(
                self.key,
                DES3.MODE_CBC,
                self.iv,
                padmode=None  # 使用手动填充
            )

            # 手动实现 PKCS7 填充
            block_size = DES3.block_size
            padding_length = block_size - (len(plain_text.encode()) % block_size)
            padded_data = plain_text.encode() + bytes([padding_length] * padding_length)

            # 加密
            encrypted_data = cipher.encrypt(padded_data)
            return base64.b64encode(encrypted_data).decode('utf-8')
        except Exception as e:
            logging.error(f"加密失败: {e}")
            return plain_text

    def process_json_data(self, json_data: dict) -> tuple[dict, bool]:
        """处理JSON数据"""
        modified = False
        for field in self.encryption_fields:
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
                    logging.error(traceback.format_exc())
        return json_data, modified

    def process_form_data(self, form_data: str) -> tuple[str, bool]:
        """处理表单数据"""
        params = parse_qs(form_data, keep_blank_values=True)
        modified = False

        for field in self.encryption_fields:
            if field in params:
                try:
                    values = params[field]
                    if isinstance(values, list):
                        encrypted_values = []
                        for value in values:
                            logging.info(f"表单字段 {field} 待加密值: {value}")
                            encrypted_values.append(self.encrypt_value(value))
                        params[field] = encrypted_values
                    else:
                        logging.info(f"表单字段 {field} 待加密值: {values}")
                        params[field] = self.encrypt_value(values)
                    modified = True
                    logging.info(f"表单字段 {field} 加密完成")
                except Exception as e:
                    logging.error(f"加密字段 {field} 失败: {e}")

        for key in params:
            if isinstance(params[key], list) and len(params[key]) == 1:
                params[key] = params[key][0]

        return urlencode(params), modified

    def request(self, flow: http.HTTPFlow) -> None:
        """处理请求"""
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
addons = [Des3EncryptInterceptor(encryption_fields, key, iv)]
