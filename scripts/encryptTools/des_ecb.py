"""
DES-ECB 加密脚本-已测试√√

使用方法:
    mitmdump -p 8888 -s des_ecb.py --ssl-insecure field=password key=your_key

参数说明:
    field: 需要处理的字段，多个字段用逗号分隔
    key: DES密钥，长度必须为8字节

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段处理
    3. 密钥长度必须符合要求
    4. ECB模式不需要IV
    5. 加密结果使用 Base64 编码
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
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad

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

def get_des_config() -> str:
    """获取DES配置"""
    key = None
    for arg in sys.argv:
        if arg.startswith('key='):
            key = arg.replace('key=', '').strip()
    
    if not key:
        raise ValueError("必须提供key参数")
    
    # 模拟 JavaScript 的 forge.util.createBuffer().toHex() 处理
    key_hex = key.encode('utf-8').hex()
    
    # 模拟 JavaScript 的 forge.util.hexToBytes() 处理
    key_bytes = bytes.fromhex(key_hex)
    
    # 验证密钥长度
    if len(key_bytes) != 8:
        raise ValueError(f"无效的DES密钥长度: {len(key_bytes)}字节，应为8字节")
    
    # 添加调试日志
    print(f"密钥原始值: {key}")
    print(f"密钥十六进制: {key_hex}")
    print(f"密钥字节: {key_bytes}")
    
    return key

def get_log_filename(fields: List[str]) -> str:
    """生成日志文件名"""
    return f"des_ecb_{'_'.join(fields)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

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

    def _format_log_message(self, url: str, field: str, original: str, processed: str) -> str:
        """格式化日志消息"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        packet_number = get_packet_number(url, original)
        
        return (
            f"[{timestamp}] #{packet_number} URL: {url}\n"
            f"字段: {field}\n"
            f"原始值: {original}\n"
            f"加密值: {processed}\n"
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
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)

class DesEcbEncryptInterceptor:
    """DES-ECB 加密拦截器"""
    
    def __init__(self, encryption_fields: List[str], key: str):
        self.encryption_fields = encryption_fields
        self.key = key.encode('utf-8')
        self._lock = threading.Lock()
        self.logger = AsyncLogger()
        self._initialized = True  # 添加初始化标志

    def encrypt_value(self, plain_text: str, url: str, field: str) -> str:
        """加密单个值"""
        if not hasattr(self, '_initialized'):  # 检查是否已初始化
            return plain_text
            
        try:
            # 创建新的cipher实例
            cipher = DES.new(self.key, DES.MODE_ECB)
            
            # 加密数据
            padded_data = pad(plain_text.encode('utf-8'), DES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            encrypted_text = base64.b64encode(encrypted_data).decode('utf-8')
            
            return encrypted_text
        except Exception as e:
            error_msg = f"加密失败: {str(e)}"
            raise

    def process_json_data(self, data: Dict[str, Any], url: str) -> Tuple[Dict[str, Any], bool]:
        """处理JSON数据"""
        if not hasattr(self, '_initialized'):  # 检查是否已初始化
            return data, False
            
        modified = False
        # 使用 separators 参数去除多余的空格
        original_data = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
        
        def process_nested_dict(d: Dict[str, Any], path: str = "") -> None:
            nonlocal modified
            for key, value in d.items():
                current_path = f"{path}.{key}" if path else key
                
                # 如果当前字段在加密字段列表中
                if current_path in self.encryption_fields:
                    try:
                        # 如果值是字典，将其转换为JSON字符串后加密
                        if isinstance(value, dict):
                            # 将对象转换为JSON字符串，使用 separators 参数去除多余的空格
                            value_str = json.dumps(value, separators=(',', ':'), ensure_ascii=False)
                            # 加密JSON字符串
                            encrypted_value = self.encrypt_value(value_str, url, current_path)
                            # 将加密后的值作为字符串存储
                            d[key] = encrypted_value
                            modified = True
                        # 如果值是字符串，直接加密
                        elif isinstance(value, str):
                            encrypted_value = self.encrypt_value(value, url, current_path)
                            d[key] = encrypted_value
                            modified = True
                    except Exception as e:
                        self.logger.log(None, self.logger._format_log_message(url, current_path, original_data, f"加密失败: {str(e)}"))
                # 如果当前字段不在加密字段列表中，但值是字典，继续递归处理
                elif isinstance(value, dict):
                    process_nested_dict(value, current_path)
        
        process_nested_dict(data)
        
        # 只在数据被修改时记录日志，并且只记录最终的加密结果
        if modified:
            final_data = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
            self.logger.log(None, self.logger._format_log_message(url, 'data', original_data, final_data))
        
        return data, modified

    def process_form_data(self, form_data: str, url: str) -> Tuple[str, bool]:
        """处理表单数据"""
        if not hasattr(self, '_initialized'):  # 检查是否已初始化
            return form_data, False
            
        try:
            parsed_data = parse_qs(form_data, keep_blank_values=True)
            modified = False
            
            for field in self.encryption_fields:
                if field in parsed_data:
                    try:
                        value = parsed_data[field][0]
                        encrypted_value = self.encrypt_value(value, url, field)
                        parsed_data[field] = [encrypted_value]
                        modified = True
                    except Exception as e:
                        self.logger.log(None, self.logger._format_log_message(url, field, value, f"加密失败: {str(e)}"))
            
            if modified:
                return urlencode(parsed_data, doseq=True), True
            return form_data, False
            
        except Exception as e:
            self.logger.log(None, self.logger._format_log_message(url, "", form_data, f"处理表单数据失败: {str(e)}"))
            return form_data, False

    @concurrent
    def request(self, flow: http.HTTPFlow) -> None:
        """处理请求"""
        if STOP_EVENT.is_set() or not hasattr(self, '_initialized'):  # 检查是否已初始化
            return
            
        try:
            content_type = flow.request.headers.get("Content-Type", "")
            url = self._get_request_url(flow)
            
            with self._lock:
                modified = False
                if "application/json" in content_type:
                    try:
                        json_data = json.loads(flow.request.content)
                        # 检查是否已经加密过
                        if isinstance(json_data, dict) and 'data' in json_data and isinstance(json_data['data'], str):
                            return
                        json_data, modified = self.process_json_data(json_data, url)
                        if modified:
                            flow.request.content = json.dumps(json_data, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
                            flow.request.headers["Content-Length"] = str(len(flow.request.content))
                    except json.JSONDecodeError as e:
                        return

                elif "application/x-www-form-urlencoded" in content_type:
                    try:
                        form_data = flow.request.content.decode('utf-8')
                        new_content, modified = self.process_form_data(form_data, url)
                        if modified:
                            flow.request.content = new_content.encode('utf-8')
                            flow.request.headers["Content-Length"] = str(len(flow.request.content))
                    except UnicodeDecodeError as e:
                        return

        except Exception as e:
            pass

    def _get_request_url(self, flow: http.HTTPFlow) -> str:
        """获取请求URL"""
        return f"{flow.request.scheme}://{flow.request.host}{flow.request.path}"

    def done(self) -> None:
        """脚本退出时的清理函数"""
        global STOP_EVENT
        STOP_EVENT.set()
        self.logger.stop()

# 获取配置
try:
    fields = get_fields()
    key = get_des_config()
except Exception as e:
    print(f"配置错误: {str(e)}", file=sys.stderr)
    sys.exit(1)

# 注册插件
addons = [DesEcbEncryptInterceptor(fields, key)] 