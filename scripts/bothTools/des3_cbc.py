"""
3DES CBC 双向加解密脚本-已测试

使用方法:
    加密: mitmdump -p 9999 -s des3_cbc.py --ssl-insecure field=password key=your_key iv=your_iv
    解密: mitmdump -p 8888 -s des3_cbc.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password key=your_key iv=your_iv

参数说明:
    field: 需要处理的字段，多个字段用逗号分隔
    key: 3DES密钥
    iv: 初始化向量（CBC模式需要）

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段解密
    3. 3DES密钥必须是24字节长度
    4. 初始化向量必须是8字节长度
    5. 解密前的数据需要是Base64编码
"""

import sys
from mitmproxy import http
from mitmproxy.script import concurrent
import json
from urllib.parse import parse_qs, urlencode, quote
import threading
import queue
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
import os
from datetime import datetime
from Crypto.Cipher import DES3
import base64
from Crypto.Util.Padding import unpad, pad
from typing import List

def get_decryption_config():
    """从命令行参数获取解密配置"""
    all_args = sys.argv
    decryption_fields = []
    des3_key = None
    iv = None

    for arg in all_args:
        if arg.startswith('field='):
            fields = arg.replace('field=', '')
            decryption_fields = [field.strip() for field in fields.split(',') if field.strip()]
        elif arg.startswith('key='):
            des3_key = arg.replace('key=', '').strip()
        elif arg.startswith('iv='):
            iv = arg.replace('iv=', '').strip()

    return decryption_fields, des3_key, iv

def get_mode():
    """获取运行模式"""
    all_args = sys.argv
    mode = 'encrypt'  # 默认模式为加密
    for arg in all_args:
        if arg == '--mode' or arg.startswith('--mode='):
            mode = 'decrypt'  # 有--mode参数就是解密模式
            break
    return mode

# 获取解密配置
decryption_fields, des3_key, iv = get_decryption_config()
mode = get_mode()

class AsyncLogger:
    _instance = None
    _lock = threading.Lock()
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(AsyncLogger, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    def __init__(self):
        if self._initialized:
            return
        with self._lock:
            if self._initialized:
                return
            self.log_queue = queue.Queue()
            self.running = True
            self.thread = threading.Thread(target=self._process_logs, daemon=True)
            self.thread.start()
            self.log_dir = "logs"
            if not os.path.exists(self.log_dir):
                os.makedirs(self.log_dir)
            script_name = os.path.splitext(os.path.basename(__file__))[0]
            self.log_file = os.path.join(self.log_dir, f"both_{script_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
            self._initialized = True
            self.fields = []
    def _process_logs(self):
        while self.running:
            try:
                log_entry = self.log_queue.get_nowait()
                if log_entry:
                    flow, comment = log_entry
                    with open(self.log_file, 'a', encoding='utf-8') as f:
                        f.write(comment + '\n')
            except queue.Empty:
                time.sleep(0.1)
            except Exception as e:
                print(f"日志处理错误: {str(e)}")
    def log(self, flow, comment):
        try:
            self.log_queue.put_nowait((flow, comment))
        except queue.Full:
            try:
                self.log_queue.get_nowait()
                self.log_queue.put_nowait((flow, comment))
            except Exception as e:
                print(f"日志队列错误: {str(e)}")
    def stop(self):
        self.running = False
        if self.thread.is_alive():
            self.thread.join()
    def _format_log_message(self, url: str, field: str, original: str, processed: str, mode: str) -> str:
        """格式化日志消息"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # 使用 URL 和原始内容作为键来获取数据包序号
        packet_number = get_packet_number(url, original)
        
        # 根据模式格式化日志消息
        if mode == 'encrypt':
            return (
                f"[{timestamp}] #{packet_number} URL: {url}\n"
                f"模式: {mode}\n"
                f"字段: {field}\n"
                f"原始值: {original}\n"
                f"加密值: {processed}\n"
                f"{'='*50}\n"
            )
        else:  # decrypt 模式
            return (
                f"[{timestamp}] #{packet_number} URL: {url}\n"
                f"模式: {mode}\n"
                f"字段: {field}\n"
                f"原始值: {original}\n"
                f"解密值: {processed}\n"
                f"{'='*50}\n"
            )

def get_packet_number(url: str, content: str) -> int:
    """获取数据包序号"""
    key = f"{url}_{content}"
    if not hasattr(get_packet_number, 'counter'):
        get_packet_number.counter = {}
    if key not in get_packet_number.counter:
        get_packet_number.counter[key] = 1
    else:
        get_packet_number.counter[key] += 1
    return get_packet_number.counter[key]

class DES3CBCBothInterceptor:
    """3DES-CBC 双向加解密拦截器"""

    def __init__(self, fields: List[str], key: str, iv: str):
        """初始化拦截器"""
        self.decryption_fields = fields
        self.key = key.encode('utf-8')
        self.iv = iv.encode('utf-8')
        self._lock = threading.Lock()
        self.logger = AsyncLogger()
        self.logger.fields = fields  # 传递字段列表到logger
        self.mode = get_mode()  # 从全局获取模式

    def process_value(self, value: str, url: str, field: str, is_request: bool = True) -> str:
        try:
            cipher = DES3.new(self.key, DES3.MODE_CBC, self.iv)
            # 根据 mode 判断是加密还是解密
            if self.mode == 'decrypt':  # 解密模式
                encrypted_data = base64.b64decode(value)
                decrypted_data = unpad(cipher.decrypt(encrypted_data), DES3.block_size)
                return decrypted_data.decode('utf-8')
            else:  # 加密模式
                padded = pad(value.encode('utf-8'), DES3.block_size)
                encrypted = cipher.encrypt(padded)
                return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            raise

    def process_form_data(self, form_data: str, url: str = None) -> tuple[str, bool]:
        """处理表单数据"""
        params = parse_qs(form_data, keep_blank_values=True)
        modified = False
        new_params = {}

        for key, value in params.items():
            if key in self.decryption_fields:
                try:
                    # 只处理需要加解密的字段
                    if self.mode == 'encrypt':
                        new_params[key] = self.process_value(value[0], url, key)
                    else:
                        new_params[key] = self.process_value(value[0], url, key)
                    modified = True
                except Exception as e:
                    self.logger.log(url, f"处理表单字段 {key} 失败: {str(e)}")
                    new_params[key] = value[0]  # 如果处理失败，保持原值
            else:
                # 其他字段保持原样
                new_params[key] = value[0]

        # 记录完整的表单数据日志
        if modified:
            self.logger.log(url, self.logger._format_log_message(
                url,
                ','.join(self.decryption_fields),
                form_data,  # 使用原始表单数据
                urlencode(new_params, quote_via=quote),  # 使用处理后的表单数据
                self.mode
            ))

        return urlencode(new_params, quote_via=quote), modified

    def process_json_data(self, json_data: dict, url: str = None) -> tuple[dict, bool]:
        """处理JSON数据"""
        modified = False
        new_data = {}

        # 保持所有原始字段
        for key, value in json_data.items():
            if key in self.decryption_fields:
                try:
                    # 只处理需要加解密的字段
                    if self.mode == 'encrypt':
                        # 加密时，将value转换为JSON字符串
                        value_str = json.dumps(value, separators=(',', ':'), ensure_ascii=False)
                        result = self.process_value(value_str, url, key)
                        new_data[key] = result
                    else:
                        # 解密时，先解密，再解析JSON
                        value_str = str(value)
                        result = self.process_value(value_str, url, key)
                        try:
                            # 解析JSON字符串
                            new_data[key] = json.loads(result)
                        except json.JSONDecodeError:
                            # 如果不是JSON字符串，保持原样
                            new_data[key] = result
                    modified = True
                except Exception as e:
                    # 如果处理失败，保持原值
                    new_data[key] = value
            else:
                # 其他字段保持原样
                new_data[key] = value

        # 记录完整的JSON数据日志
        if modified:
            # 使用压缩格式的JSON
            original_json = json.dumps(json_data, separators=(',', ':'), ensure_ascii=False)
            processed_json = json.dumps(new_data, separators=(',', ':'), ensure_ascii=False)
            
            # 记录完整的请求数据
            self.logger.log(url, self.logger._format_log_message(
                url,
                ','.join(self.decryption_fields),
                original_json,  # 使用原始JSON数据
                processed_json,  # 使用处理后的JSON数据
                self.mode
            ))

        return new_data, modified

    @concurrent
    def request(self, flow: http.HTTPFlow) -> None:
        """处理请求"""
        try:
            content_type = flow.request.headers.get("Content-Type", "")
            
            with self._lock:
                modified = False
                try:
                    # 尝试解码请求内容
                    original_content = flow.request.content.decode('utf-8')
                except UnicodeDecodeError:
                    # 如果解码失败，可能是二进制数据，直接返回
                    return
                
                processed_content = original_content

                if "application/json" in content_type:
                    try:
                        json_data = json.loads(original_content)
                        json_data, modified = self.process_json_data(json_data, flow.request.url)
                        if modified:
                            processed_content = json.dumps(json_data, separators=(',', ':'), ensure_ascii=False)
                            flow.request.content = processed_content.encode('utf-8')
                    except json.JSONDecodeError as e:
                        self.logger.log(None, f"JSON解析失败: {str(e)}")
                        return

                elif "application/x-www-form-urlencoded" in content_type:
                    try:
                        processed_content, modified = self.process_form_data(original_content, flow.request.url)
                        if modified:
                            flow.request.content = processed_content.encode('utf-8')
                    except Exception as e:
                        self.logger.log(None, f"处理表单数据失败: {str(e)}")
                        return

                if modified:
                    flow.request.headers["Content-Length"] = str(len(flow.request.content))

        except Exception as e:
            self.logger.log(None, f"处理请求失败: {str(e)}")
            import traceback
            self.logger.log(None, f"错误详情:\n{traceback.format_exc()}")

    def done(self):
        """清理资源"""
        self.logger.stop()

# 注册插件
addons = [DES3CBCBothInterceptor(decryption_fields, des3_key, iv)] 