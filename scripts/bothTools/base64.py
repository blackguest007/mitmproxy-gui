"""
Base64 编解码脚本-已测试√√

使用方法:
    编码: mitmdump -p 9999 -s base64.py --ssl-insecure field=password
    解码: mitmdump -p 8888 -s base64.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password

参数说明:
    field: 需要处理的字段，多个字段用逗号分隔

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段处理
"""

import sys
from mitmproxy import http
from mitmproxy.script import concurrent
import json
from urllib.parse import parse_qs, urlencode, quote, unquote
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

def get_fields() -> List[str]:
    """从命令行参数获取配置"""
    for arg in sys.argv:
        if arg.startswith('field='):
            return [field.strip() for field in arg.replace('field=', '').split(',') if field.strip()]
    return ['password']  # 默认字段

def get_mode() -> str:
    """获取运行模式"""
    all_args = sys.argv
    mode = 'encrypt'  # 默认模式为加密
    for arg in all_args:
        if arg == '--mode' or arg.startswith('--mode='):
            mode = 'decrypt'  # 有--mode参数就是解密模式
            break
    return mode

def get_log_filename(fields: List[str]) -> str:
    """生成日志文件名"""
    return f"base64_{'_'.join(fields)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

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
                
            # 创建日志文件，使用both模式命名
            script_name = os.path.splitext(os.path.basename(__file__))[0]
            self.log_file = os.path.join(self.log_dir, f"both_{script_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
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

class Base64BothInterceptor:
    """Base64 双向加解密拦截器"""
    
    def __init__(self, decryption_fields):
        self.decryption_fields = decryption_fields
        self._lock = threading.Lock()
        self.logger = AsyncLogger()
        self.logger.fields = decryption_fields  # 传递字段列表到logger

    def process_value(self, value: str, url: str, field: str, is_request: bool = True) -> str:
        try:
            # 根据 mode 判断是加密还是解密
            if mode == 'decrypt':  # 解密模式
                try:
                    # 尝试Base64解码单个字段
                    decrypted_data = base64.b64decode(value)
                    result = decrypted_data.decode('utf-8')
                    return result
                except (base64.binascii.Error, UnicodeDecodeError) as e:
                    self.logger.log(url, f"解密失败: {str(e)}")
                    raise
            else:  # 加密模式
                encrypted_data = base64.b64encode(value.encode('utf-8'))
                result = encrypted_data.decode('utf-8')
                return result
        except Exception as e:
            self.logger.log(url, f"{'加密' if mode == 'encrypt' else '解密'}失败: {str(e)}")
            raise

    def process_form_data(self, form_data: str, url: str = None) -> tuple[str, bool]:
        """处理表单数据"""
        params = parse_qs(form_data, keep_blank_values=True)
        modified = False
        new_params = {}

        # 保持所有原始字段，去掉列表形式
        for key, value in params.items():
            # 获取列表中的第一个值，如果没有则为空字符串
            value_str = value[0] if value else ''
            if key in self.decryption_fields:
                try:
                    # 只处理需要加解密的字段
                    new_params[key] = self.process_value(value_str, url, key)
                    modified = True
                except Exception as e:
                    self.logger.log(url, f"处理表单字段 {key} 失败: {str(e)}")
                    new_params[key] = value_str  # 如果处理失败，保持原值
            else:
                # 其他字段保持原样
                new_params[key] = value_str

        # 记录完整的表单数据日志
        if modified:
            # 构建原始表单数据字符串，直接使用值而不是列表
            original_form = '&'.join(f"{k}={v}" for k, v in params.items() for v in [v[0] if v else ''])
            # 构建处理后的表单数据字符串
            processed_form = '&'.join(f"{k}={v}" for k, v in new_params.items())
            
            self.logger.log(url, self.logger._format_log_message(
                url,
                ','.join(self.decryption_fields),
                original_form,  # 使用原始表单数据
                processed_form,  # 使用处理后的表单数据
                mode
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
                    value_str = str(value)
                    new_data[key] = self.process_value(value_str, url, key)
                    modified = True
                except Exception as e:
                    self.logger.log(url, f"处理JSON字段 {key} 失败: {str(e)}")
                    new_data[key] = value  # 如果处理失败，保持原值
            else:
                # 其他字段保持原样
                new_data[key] = value

        # 记录完整的JSON数据日志
        if modified:
            # 使用压缩格式的JSON
            original_json = json.dumps(json_data, separators=(',', ':'), ensure_ascii=False)
            processed_json = json.dumps(new_data, separators=(',', ':'), ensure_ascii=False)
            
            self.logger.log(url, self.logger._format_log_message(
                url,
                ','.join(self.decryption_fields),
                original_json,  # 使用原始JSON数据
                processed_json,  # 使用处理后的JSON数据
                mode
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
                    # 直接解码请求内容
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
                    except json.JSONDecodeError:
                        self.logger.log(None, f"JSON解析失败: {original_content}")

                elif "application/x-www-form-urlencoded" in content_type:
                    processed_content, modified = self.process_form_data(original_content, flow.request.url)
                    if modified:
                        flow.request.content = processed_content.encode('utf-8')

                if modified:
                    flow.request.headers["Content-Length"] = str(len(flow.request.content))

        except Exception as e:
            self.logger.log(None, f"处理请求失败: {str(e)}")

    def done(self):
        """清理资源"""
        self.logger.stop()

# 获取配置
fields = get_fields()
mode = get_mode()

# 注册插件
addons = [Base64BothInterceptor(fields)] 