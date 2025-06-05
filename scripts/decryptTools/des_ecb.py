"""
DES-ECB 解密脚本-已测试√√

使用方法:
    mitmdump -p 8888 -s des_ecb.py --ssl-insecure field=password key=your_key

参数说明:
    field: 需要处理的字段，多个字段用逗号分隔
    key: DES密钥，长度必须为8字节

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段处理
    3. 密钥长度必须符合要求
    4. 解密前的数据需要是Base64编码
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
from Crypto.Util.Padding import unpad

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
    
    # 直接使用 UTF-8 编码，与 CryptoJS.enc.Utf8.parse() 保持一致
    key_bytes = key.encode('utf-8')
    
    # 验证密钥长度
    if len(key_bytes) != 8:
        raise ValueError(f"无效的DES密钥长度: {len(key_bytes)}字节，应为8字节")
    
    # 添加调试日志
    print(f"密钥原始值: {key}")
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
                
            # 创建日志文件，使用decrypt前缀
            script_name = os.path.splitext(os.path.basename(__file__))[0]
            self.log_file = os.path.join(self.log_dir, f"decrypt_{script_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
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
            f"解密值: {processed}\n"
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

class DesEcbDecryptInterceptor:
    """DES-ECB 解密拦截器"""
    
    def __init__(self, decryption_fields: List[str], key: str):
        self.decryption_fields = decryption_fields
        self.key = key.encode('utf-8')
        self._lock = threading.Lock()
        self.logger = AsyncLogger()
        self._initialized = True  # 添加初始化标志

    def decrypt_value(self, encrypted_text: str, url: str, field: str) -> str:
        """解密单个值"""
        if not hasattr(self, '_initialized'):  # 检查是否已初始化
            return encrypted_text
            
        try:
            # 添加调试日志
            print(f"\n=== 解密过程 ===")
            print(f"加密文本: {encrypted_text}")
            print(f"密钥: {self.key}")
            
            # 创建新的cipher实例
            cipher = DES.new(self.key, DES.MODE_ECB)
            
            # 解密数据
            encrypted_data = base64.b64decode(encrypted_text)
            print(f"Base64解码后: {encrypted_data}")
            
            decrypted_data = cipher.decrypt(encrypted_data)
            print(f"解密后(带填充): {decrypted_data}")
            
            unpadded_data = unpad(decrypted_data, DES.block_size)
            print(f"去除填充后: {unpadded_data}")
            
            decrypted_text = unpadded_data.decode('utf-8')
            print(f"最终文本: {decrypted_text}")
            print("=== 解密完成 ===\n")
            
            return decrypted_text
        except Exception as e:
            error_msg = f"解密失败: {str(e)}"
            print(f"解密错误: {error_msg}")
            raise

    def process_json_data(self, data: Dict[str, Any], url: str) -> Tuple[Dict[str, Any], bool]:
        """处理JSON数据"""
        if not hasattr(self, '_initialized'):  # 检查是否已初始化
            return data, False
            
        modified = False
        # 使用 separators 参数去除多余的空格
        original_data = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
        
        for field in self.decryption_fields:
            if field in data and isinstance(data[field], str):
                try:
                    # 保存原始加密值
                    original_encrypted = data[field]
                    
                    # 解密数据
                    decrypted_value = self.decrypt_value(data[field], url, field)
                    try:
                        # 尝试将解密后的值解析为JSON
                        data[field] = json.loads(decrypted_value)
                    except json.JSONDecodeError:
                        data[field] = decrypted_value
                    modified = True
                    
                    # 记录日志，显示原始加密值和解密后的值
                    self.logger.log(None, self.logger._format_log_message(
                        url,
                        field,
                        json.dumps({field: original_encrypted}, ensure_ascii=False),
                        json.dumps({field: data[field]}, ensure_ascii=False)
                    ))
                except Exception as e:
                    # 记录解密失败
                    self.logger.log(None, self.logger._format_log_message(
                        url,
                        field,
                        json.dumps({field: data[field]}, ensure_ascii=False),
                        json.dumps({field: f"解密失败: {str(e)}"}, ensure_ascii=False)
                    ))
                    continue
                    
        return data, modified

    def process_form_data(self, form_data: str, url: str) -> Tuple[str, bool]:
        """处理表单数据"""
        if not hasattr(self, '_initialized'):  # 检查是否已初始化
            return form_data, False
            
        try:
            parsed_data = parse_qs(form_data, keep_blank_values=True)
            modified = False
            
            for field in self.decryption_fields:
                if field in parsed_data:
                    try:
                        # 保存原始加密值
                        original_encrypted = parsed_data[field][0]
                        
                        # 解密数据
                        decrypted_value = self.decrypt_value(original_encrypted, url, field)
                        parsed_data[field] = [decrypted_value]
                        modified = True
                        
                        # 记录日志，显示原始加密值和解密后的值
                        try:
                            decrypted_json = json.loads(decrypted_value)
                            self.logger.log(None, self.logger._format_log_message(
                                url,
                                field,
                                json.dumps({field: original_encrypted}, ensure_ascii=False),
                                json.dumps({field: decrypted_json}, ensure_ascii=False)
                            ))
                        except json.JSONDecodeError:
                            # 如果不是JSON格式，直接记录字符串
                            self.logger.log(None, self.logger._format_log_message(
                                url,
                                field,
                                json.dumps({field: original_encrypted}, ensure_ascii=False),
                                json.dumps({field: decrypted_value}, ensure_ascii=False)
                            ))
                    except Exception as e:
                        # 记录解密失败
                        self.logger.log(None, self.logger._format_log_message(
                            url,
                            field,
                            json.dumps({field: original_encrypted}, ensure_ascii=False),
                            json.dumps({field: f"解密失败: {str(e)}"}, ensure_ascii=False)
                        ))
                        continue
            
            if modified:
                return urlencode(parsed_data, doseq=True), True
            return form_data, False
            
        except Exception as e:
            error_msg = f"处理表单数据失败: {str(e)}"
            self.logger.log(None, self.logger._format_log_message(url, "", form_data, error_msg))
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
addons = [DesEcbDecryptInterceptor(fields, key)] 