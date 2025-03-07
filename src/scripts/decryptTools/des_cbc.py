"""
DES-CBC 解密脚本

使用方法:
    mitmdump -p 8888 -s des_cbc.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=data key=12345678 iv=12345678

参数说明:
    -p 8888: 监听端口
    -s des_cbc.py: 指定脚本文件
    --mode upstream:http://127.0.0.1:8080: 指定代理服务器
    --ssl-insecure: 忽略 SSL 证书验证
    field: 需要解密的字段名称，多个字段用逗号分隔
    key: DES密钥，必须是8字节长度
    iv: 初始化向量，必须是8字节长度

注意事项:
    1. DES密钥和IV必须是8字节长度
    2. 支持 application/json 和 application/x-www-form-urlencoded 格式
    3. 解密前数据需为 Base64 编码
"""

import sys
from mitmproxy import http
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
import base64
import logging
import json
from urllib.parse import parse_qs, urlencode

# 配置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_decryption_fields():
    """获取解密配置"""
    all_args = sys.argv[1:]
    decryption_fields = []
    key = None
    iv = None

    for arg in all_args:
        if not arg.startswith('-'):
            if 'key=' in arg:
                key = arg.split('=')[1]
            elif 'iv=' in arg:
                iv = arg.split('=')[1]
            elif 'field=' in arg:  # 修改这里，明确检查 field= 前缀
                fields = arg.split('=')[1]
                decryption_fields = [field.strip() for field in fields.split(',') if field.strip()]

    logging.info(f"需要解密的字段: {decryption_fields}")
    return decryption_fields, key, iv


class DesDecryptInterceptor:
    def __init__(self, decryption_fields, key, iv):
        self.decryption_fields = decryption_fields
        self.key = key.encode('utf-8')
        self.iv = iv.encode('utf-8')

    def decrypt_value(self, encrypted_text: str) -> str:
        """解密单个值"""
        try:
            # 确保数据是 Base64 编码的
            encrypted_data = base64.b64decode(encrypted_text)
            cipher = DES.new(self.key, DES.MODE_CBC, self.iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), DES.block_size)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            logging.error(f"解密失败: {e}")
            return encrypted_text

    def process_json_data(self, json_data: dict) -> tuple[dict, bool]:
        """处理JSON数据"""
        modified = False
        for field in self.decryption_fields:
            if field in json_data:
                try:
                    encrypted_value = json_data[field]
                    logging.info(f"JSON字段 {field} 待解密值: {encrypted_value}")
                    decrypted_value = self.decrypt_value(encrypted_value)

                    # 解析解密后的字符串为 JSON 对象
                    json_data[field] = json.loads(decrypted_value)  # 确保将解密后的字符串解析为 JSON 对象
                    modified = True
                    logging.info(f"JSON字段 {field} 解密完成")
                except Exception as e:
                    logging.error(f"解密字段 {field} 失败: {e}")
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
                        decrypted_values = []
                        for value in values:
                            logging.info(f"表单字段 {field} 待解密值: {value}")
                            decrypted_values.append(self.decrypt_value(value))
                        params[field] = decrypted_values
                    else:
                        logging.info(f"表单字段 {field} 待解密值: {values}")
                        params[field] = self.decrypt_value(values)
                    modified = True
                    logging.info(f"表单字段 {field} 解密完成")
                except Exception as e:
                    logging.error(f"解密字段 {field} 失败: {e}")

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

            # 显示原始请求数据包
            logging.info(f"原始请求数据包: {flow.request.content.decode('utf-8')}")

            modified = False
            if "application/json" in content_type:
                json_data = json.loads(flow.request.content)
                json_data, modified = self.process_json_data(json_data)
                if modified:
                    flow.request.content = json.dumps(json_data).encode('utf-8')

            elif "application/x-www-form-urlencoded" in content_type:
                form_data = flow.request.content.decode('utf-8')
                new_content, modified = self.process_form_data(form_data)
                if modified:
                    flow.request.content = new_content.encode('utf-8')

            if modified:
                flow.request.headers["Content-Length"] = str(len(flow.request.content))
                logging.info("\n解密后的请求数据包:")
                logging.info(f"{flow.request.content.decode('utf-8')}")

            logging.info("=" * 50)

        except Exception as e:
            logging.error(f"处理请求失败: {e}")
            import traceback
            logging.error(traceback.format_exc())


# 获取解密配置
decryption_fields, key, iv = get_decryption_fields()

# 注册插件
addons = [DesDecryptInterceptor(decryption_fields, key, iv)]
