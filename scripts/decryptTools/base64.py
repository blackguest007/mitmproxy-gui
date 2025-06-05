"""
Base64 解密脚本-已测试√√

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

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段处理
    3. Base64解密前需要是标准Base64编码字符串
    4. 日志文件保存在 logs 目录下，格式为: decrypt_base64_时间戳.log

日志格式示例:
    1. 表单数据:
    [2024-03-21 10:30:45] #1 URL: http://example.com/login
    字段: password
    原始值: m=2&username=admin&password=YWRtaW4=
    解密值: m=2&username=admin&password=admin
    ==================================================

    2. JSON数据:
    [2024-03-21 10:30:45] #1 URL: http://example.com/api
    字段: password
    原始值: {"username":"admin","password":"YWRtaW4="}
    解密值: {"username":"admin","password":"admin"}
    ==================================================
"""

import sys
from mitmproxy import http
import base64
import json
from urllib.parse import parse_qs, urlencode, unquote
import threading
import queue
import time
import os
from datetime import datetime
from typing import Dict, List, Tuple, Any

# 全局日志计数器
LOG_COUNTER = 0
LOG_COUNTER_LOCK = threading.Lock()
# 用于存储数据包的序号
PACKET_COUNTERS = {}
PACKET_COUNTERS_LOCK = threading.Lock()

def get_packet_number(url: str, content: str) -> int:
    """获取数据包的序号，相同的数据包返回相同的序号"""
    global LOG_COUNTER, PACKET_COUNTERS
    # 使用URL和内容的哈希值作为键，避免存储过长的字符串
    packet_key = hash(f"{url}:{content}")
    
    with PACKET_COUNTERS_LOCK:
        if packet_key not in PACKET_COUNTERS:
            with LOG_COUNTER_LOCK:
                LOG_COUNTER += 1
                PACKET_COUNTERS[packet_key] = LOG_COUNTER
        return PACKET_COUNTERS[packet_key]

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

    return decryption_fields

class AsyncLogger:
    """异步日志处理器"""
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
                
            self.log_queue = queue.Queue(maxsize=1000)  # 设置较大的队列大小
            self.running = True
            self.thread = threading.Thread(target=self._process_logs, daemon=True)
            self.thread.start()
            
            # 创建日志目录
            self.log_dir = "logs"
            if not os.path.exists(self.log_dir):
                os.makedirs(self.log_dir)
                
            # 创建日志文件，使用decrypt模式命名
            script_name = os.path.splitext(os.path.basename(__file__))[0]
            self.log_file = os.path.join(self.log_dir, f"decrypt_{script_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
            self._initialized = True
            self.fields = []  # 初始化字段列表
            self.last_flush_time = time.time()  # 添加最后刷新时间记录

    def _format_log_message(self, url: str, field: str, original: str, processed: str, full_json: Dict[str, Any] = None, form_data: str = "") -> str:
        """格式化日志消息"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # 使用 URL 和原始内容作为键来获取数据包序号
        packet_number = get_packet_number(url, original)
        
        # 根据数据类型选择显示格式
        if full_json:
            processed_value = json.dumps(full_json, ensure_ascii=False)
        elif form_data:
            # 对于表单数据，保持原始格式，只替换解密后的值
            params = parse_qs(form_data, keep_blank_values=True)
            if field in params:
                params[field] = [processed] if isinstance(params[field], list) else processed
            processed_value = "&".join([f"{k}={v[0] if isinstance(v, list) else v}" for k, v in params.items()])
        else:
            processed_value = processed
            
        return (
            f"[{timestamp}] #{packet_number} URL: {url}\n"
            f"字段: {field}\n"
            f"原始值: {original}\n"
            f"解密值: {processed_value}\n"
            f"{'='*50}\n"
        )

    def _process_logs(self):
        """处理日志队列"""
        while self.running:
            try:
                # 非阻塞方式获取日志，设置较短的超时时间
                log_entry = self.log_queue.get(timeout=0.01)
                if log_entry:
                    flow, comment = log_entry
                    # 立即写入文件
                    with open(self.log_file, 'a', encoding='utf-8') as f:
                        f.write(comment + '\n')
                        f.flush()  # 强制刷新文件缓冲区
                        os.fsync(f.fileno())  # 确保写入磁盘
            except queue.Empty:
                # 队列为空时短暂休眠
                time.sleep(0.001)  # 减少休眠时间
            except Exception as e:
                pass

    def log(self, flow, comment):
        """添加日志到队列"""
        try:
            # 使用非阻塞方式添加日志
            self.log_queue.put_nowait((flow, comment))
        except queue.Full:
            # 队列满时，立即处理一些日志
            try:
                # 处理一条日志
                log_entry = self.log_queue.get_nowait()
                flow, comment = log_entry
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.write(comment + '\n')
                    f.flush()
                    os.fsync(f.fileno())
                # 然后添加新日志
                self.log_queue.put_nowait((flow, comment))
            except Exception:
                pass

    def stop(self):
        """停止日志处理"""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)

class Base64DecodeInterceptor:
    def __init__(self, decryption_fields):
        self.decryption_fields = decryption_fields
        self.logger = AsyncLogger()
        self.logger.fields = decryption_fields  # 传递字段列表到logger

    def is_valid_base64(self, s: str) -> bool:
        """检查字符串是否是有效的Base64编码"""
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

    def decode_value(self, encoded_text: str, url: str, field: str, full_json: Dict[str, Any] = None, form_data: str = "") -> str:
        """Base64解码"""
        try:
            # 检查是否是有效的Base64编码
            if not self.is_valid_base64(encoded_text):
                return encoded_text

            decoded_bytes = base64.b64decode(encoded_text)
            decoded_text = decoded_bytes.decode('utf-8')
            self.logger.log(None, self.logger._format_log_message(url, field, encoded_text, decoded_text, full_json, form_data))
            return decoded_text
        except Exception as e:
            error_msg = f"解码失败: {str(e)}"
            self.logger.log(None, self.logger._format_log_message(url, field, encoded_text, error_msg, full_json, form_data))
            return encoded_text

    def process_json_data(self, json_data: dict, url: str) -> tuple[dict, bool]:
        """处理JSON数据"""
        modified = False
        for field in self.decryption_fields:
            if field in json_data:
                try:
                    encoded_value = json_data[field]
                    decoded_value = self.decode_value(encoded_value, url, field, json_data)
                    
                    try:
                        json_data[field] = json.loads(decoded_value)
                    except json.JSONDecodeError:
                        json_data[field] = decoded_value
                    
                    modified = True
                except Exception as e:
                    self.logger.log(None, self.logger._format_log_message(url, field, str(encoded_value), f"解码失败: {str(e)}", json_data))
        return json_data, modified

    def process_form_data(self, form_data: str, url: str) -> tuple[str, bool]:
        """处理表单数据"""
        try:
            # URL解码表单数据
            decoded_form = unquote(form_data)
            params = parse_qs(decoded_form, keep_blank_values=True)
            modified = False

            for field in self.decryption_fields:
                if field in params:
                    try:
                        values = params[field]
                        if isinstance(values, list):
                            decoded_values = []
                            for value in values:
                                decoded_value = self.decode_value(value, url, field, form_data=form_data)
                                decoded_values.append(decoded_value)
                            params[field] = decoded_values
                        else:
                            decoded_value = self.decode_value(values, url, field, form_data=form_data)
                            params[field] = decoded_value
                        modified = True
                    except Exception as e:
                        self.logger.log(None, self.logger._format_log_message(url, field, str(values), f"解码失败: {str(e)}", form_data=form_data))

            for key in params:
                if isinstance(params[key], list) and len(params[key]) == 1:
                    params[key] = params[key][0]

            if modified:
                return urlencode(params), True
            return form_data, False
            
        except Exception as e:
            self.logger.log(None, self.logger._format_log_message(url, "", form_data, f"处理表单数据失败: {str(e)}"))
            return form_data, False

    def request(self, flow: http.HTTPFlow) -> None:
        """处理请求"""
        try:
            content_type = flow.request.headers.get("Content-Type", "")
            url = f"{flow.request.scheme}://{flow.request.host}{flow.request.path}"
            
            modified = False
            if "application/json" in content_type:
                json_data = json.loads(flow.request.content)
                json_data, modified = self.process_json_data(json_data, url)
                if modified:
                    new_content = json.dumps(json_data, separators=(',', ':'))
                    flow.request.content = new_content.encode('utf-8')

            elif "application/x-www-form-urlencoded" in content_type:
                form_data = flow.request.content.decode('utf-8')
                new_content, modified = self.process_form_data(form_data, url)
                if modified:
                    flow.request.content = new_content.encode('utf-8')

            if modified:
                flow.request.headers["Content-Length"] = str(len(flow.request.content))

        except Exception as e:
            self.logger.log(None, self.logger._format_log_message(url, "", str(flow.request.content), f"处理请求失败: {str(e)}"))

# 获取解密配置
decryption_fields = get_decryption_fields()

# 注册插件
addons = [Base64DecodeInterceptor(decryption_fields)] 