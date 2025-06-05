"""
Base64 加密脚本-已测试√√

使用方法:
    mitmdump -p 8888 -s base64.py --ssl-insecure field=password
    mitmdump -p 8888 -s base64.py --ssl-insecure field=password,username

参数说明:
    field: 需要处理的字段，多个字段用逗号分隔

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段处理
    3. Base64加密结果为标准Base64编码字符串
    4. 日志文件保存在 logs 目录下，格式为: encrypt_base64_时间戳.log

日志格式示例:
    1. 表单数据:
    [2024-03-21 10:30:45] #1 URL: http://example.com/login
    字段: password
    原始值: m=2&username=admin&password=admin
    编码值: m=2&username=admin&password=YWRtaW4=
    ==================================================

    2. JSON数据:
    [2024-03-21 10:30:45] #1 URL: http://example.com/api
    字段: password
    原始值: {"username":"admin","password":"admin"}
    编码值: {"username":"admin","password":"YWRtaW4="}
    ==================================================
"""

import sys
from mitmproxy import http
from mitmproxy.script import concurrent
import json
from urllib.parse import parse_qs, urlencode
import threading
import queue
import time
import os
from datetime import datetime
import base64
import signal
from typing import Dict, List, Tuple, Optional, Any, Union

# 全局停止标志
STOP_EVENT = threading.Event()

# 日志配置
LOG_CONFIG = {
    'batch_size': 50,  # 批处理大小
    'flush_interval': 1.0,  # 文件刷新间隔（秒）
    'queue_timeout': 0.1,  # 队列获取超时时间
    'sleep_interval': 0.01,  # 空闲时睡眠时间
}

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

def get_encryption_fields() -> List[str]:
    """从命令行参数获取加密配置"""
    for arg in sys.argv:
        if arg.startswith('field='):
            return [field.strip() for field in arg.replace('field=', '').split(',') if field.strip()]
    return []

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
                
            # 创建日志文件，使用encrypt模式命名
            script_name = os.path.splitext(os.path.basename(__file__))[0]
            self.log_file = os.path.join(self.log_dir, f"encrypt_{script_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
            self._initialized = True
            self.fields = []  # 初始化字段列表
            self.last_flush_time = time.time()  # 添加最后刷新时间记录

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
                print(f"日志处理错误: {str(e)}")

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
            except Exception as e:
                print(f"日志队列处理错误: {str(e)}")

    def stop(self):
        """停止日志处理"""
        self.running = False
        if self.thread.is_alive():
            self.thread.join()

    def _format_log_message(self, url: str, field: str, original: str, processed: str, full_json: Dict[str, Any] = None, form_data: str = "") -> str:
        """格式化日志消息"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # 使用 URL 和原始内容作为键来获取数据包序号
        packet_number = get_packet_number(url, original)
        
        # 根据数据类型选择显示格式
        if full_json:
            processed_value = json.dumps(full_json, ensure_ascii=False)
        elif form_data:
            # 将表单数据转换为 key=value 格式
            params = parse_qs(form_data, keep_blank_values=True)
            processed_value = "&".join([f"{k}={v[0]}" for k, v in params.items()])
        else:
            processed_value = processed
            
        return (
            f"[{timestamp}] #{packet_number} URL: {url}\n"
            f"字段: {field}\n"
            f"原始值: {original}\n"
            f"加密值: {processed_value}\n"
            f"{'='*50}\n"
        )

class Base64EncryptInterceptor:
    """Base64 加密拦截器"""
    
    def __init__(self, encryption_fields: List[str]):
        self.encryption_fields = encryption_fields
        self._lock = threading.Lock()
        self.logger = AsyncLogger()
        self.logger.fields = encryption_fields  # 传递字段列表到logger

    def encrypt_value(self, plain_text: str, url: str, field: str, full_json: Dict[str, Any] = None, form_data: str = "") -> str:
        """加密单个值"""
        try:
            encrypted = base64.b64encode(plain_text.encode('utf-8')).decode('utf-8')
            # 记录日志
            self.logger.log(None, self.logger._format_log_message(url, field, plain_text, encrypted, full_json, form_data))
            return encrypted
        except Exception as e:
            print(f"加密失败: {str(e)}")
            return plain_text

    def _get_request_url(self, flow: http.HTTPFlow) -> str:
        """获取请求URL"""
        return f"{flow.request.scheme}://{flow.request.host}{flow.request.path}"

    @concurrent
    def request(self, flow: http.HTTPFlow) -> None:
        """处理请求"""
        if STOP_EVENT.is_set():
            return
            
        try:
            content_type = flow.request.headers.get("Content-Type", "")
            url = self._get_request_url(flow)
            
            with self._lock:
                self._handle_request_by_type(flow, url, content_type)
        except Exception as e:
            print(f"处理请求失败: {str(e)}")

    def _handle_request_by_type(self, flow: http.HTTPFlow, url: str, content_type: str) -> None:
        """根据内容类型处理请求"""
        if "application/json" in content_type:
            self._handle_json_request(flow, url)
        elif "application/x-www-form-urlencoded" in content_type:
            self._handle_form_request(flow, url)

    def _handle_json_request(self, flow: http.HTTPFlow, url: str) -> None:
        """处理JSON请求"""
        try:
            json_data = json.loads(flow.request.content)
            if self._encrypt_json_fields(json_data, url):
                self._update_json_request(flow, json_data)
        except json.JSONDecodeError as e:
            print(f"解析 JSON 数据时出错: {str(e)}")

    def _encrypt_json_fields(self, json_data: Dict[str, Any], url: str) -> bool:
        """加密JSON字段"""
        modified = False
        for field in self.encryption_fields:
            if field in json_data:
                try:
                    original = str(json_data[field])
                    encrypted = self.encrypt_value(original, url, field, json_data)
                    json_data[field] = encrypted
                    modified = True
                except Exception as e:
                    print(f"处理JSON字段 {field} 时出错: {str(e)}")
                    continue
        return modified

    def _update_json_request(self, flow: http.HTTPFlow, json_data: Dict[str, Any]) -> None:
        """更新JSON请求内容"""
        flow.request.content = json.dumps(json_data, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        flow.request.headers["Content-Length"] = str(len(flow.request.content))

    def _handle_form_request(self, flow: http.HTTPFlow, url: str) -> None:
        """处理表单请求"""
        try:
            form_data = flow.request.content.decode('utf-8')
            params = parse_qs(form_data, keep_blank_values=True)
            modified = False
            
            for field in self.encryption_fields:
                if field in params:
                    try:
                        value = params[field][0]
                        encrypted = self.encrypt_value(value, url, field, form_data=form_data)
                        if encrypted != value:
                            params[field] = [encrypted]
                            modified = True
                    except Exception as e:
                        print(f"处理表单字段 {field} 时出错: {str(e)}")
                        continue
            
            if modified:
                flow.request.content = urlencode(params, doseq=True).encode('utf-8')
                flow.request.headers["Content-Length"] = str(len(flow.request.content))
        except Exception as e:
            print(f"处理表单数据失败: {str(e)}")

    def done(self) -> None:
        """脚本退出时的清理函数"""
        global STOP_EVENT
        STOP_EVENT.set()
        self.logger.stop()

# 获取配置
try:
    fields = get_encryption_fields()
    if not fields:
        print("错误: 必须提供至少一个字段", file=sys.stderr)
        sys.exit(1)
except Exception as e:
    print(f"配置错误: {str(e)}", file=sys.stderr)
    sys.exit(1)

# 注册插件
addons = [Base64EncryptInterceptor(fields)]