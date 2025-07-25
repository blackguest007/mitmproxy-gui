"""
AES-CBC 加解密脚本-已测试√

使用方法:
    加密: mitmdump -p 9999 -s aes_cbc.py --ssl-insecure field=password key=your_key iv=your_iv
    解密: mitmdump -p 8888 -s aes_cbc.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password key=your_key iv=your_iv

参数说明:
    field: 需要处理的字段，多个字段用逗号分隔
    key: AES密钥，长度必须为16、24或32字节
    iv: 初始化向量，长度必须为16字节

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段处理
    3. 密钥和IV长度必须符合要求
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
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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

def get_aes_config() -> Tuple[str, str]:
    """获取AES配置"""
    key = None
    iv = None
    for arg in sys.argv:
        if arg.startswith('key='):
            key = arg.replace('key=', '').strip()
        elif arg.startswith('iv='):
            iv = arg.replace('iv=', '').strip()
    
    if not key or not iv:
        raise ValueError("必须提供key和iv参数")
    
    # 验证密钥和IV长度
    key_bytes = key.encode('utf-8')
    iv_bytes = iv.encode('utf-8')
    if len(key_bytes) not in [16, 24, 32]:
        raise ValueError(f"无效的AES密钥长度: {len(key_bytes)}字节，应为16/24/32字节")
    if len(iv_bytes) != 16:
        raise ValueError(f"无效的IV长度: {len(iv_bytes)}字节，应为16字节")
    
    return key, iv

def get_log_filename(fields: List[str]) -> str:
    """生成日志文件名"""
    return f"aes_cbc_{'_'.join(fields)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

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

class AesCbcBothInterceptor:
    """AES-CBC 双向加解密拦截器"""

    def __init__(self, fields: List[str], key: str, iv: str):
        """初始化拦截器"""
        self.decryption_fields = fields
        self.key = key.encode('utf-8')
        self.iv = iv.encode('utf-8')
        self._lock = threading.Lock()
        self.logger = AsyncLogger()
        self.logger.fields = fields  # 传递字段列表到logger
        self.mode = get_mode()  # 从全局获取模式

    def process_value(self, value: str, url: str, field: str) -> str:
        try:
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            # 根据全局 mode 判断是加密还是解密
            if self.mode == 'decrypt':  # 解密模式
                try:
                    # 检查输入值是否为空
                    if not value or not value.strip():
                        raise ValueError("解密数据为空")
                    
                    # 检查是否是有效的 Base64 字符串
                    try:
                        # 移除可能的 URL 安全 Base64 字符
                        value = value.replace('-', '+').replace('_', '/')
                        # 添加必要的填充
                        padding = len(value) % 4
                        if padding:
                            value += '=' * (4 - padding)
                            
                        encrypted_data = base64.b64decode(value)
                    except Exception as e:
                        raise ValueError(f"Base64 解码失败: {str(e)}")
                    
                    # 检查数据长度
                    if len(encrypted_data) == 0:
                        raise ValueError("解密数据为空")
                    if len(encrypted_data) % AES.block_size != 0:
                        raise ValueError(f"数据长度不是 AES 块大小的倍数: {len(encrypted_data)}")
                    
                    # 尝试解密
                    try:
                        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
                        return decrypted_data.decode('utf-8')
                    except ValueError as e:
                        raise ValueError(f"解密失败: {str(e)}")
                        
                except Exception as e:
                    self.logger.log(url, f"解密失败: {str(e)}")
                    raise
            else:  # 加密模式
                try:
                    # 确保输入是字符串
                    if not isinstance(value, str):
                        value = str(value)
                    
                    # 加密
                    padded = pad(value.encode('utf-8'), AES.block_size)
                    encrypted = cipher.encrypt(padded)
                    return base64.b64encode(encrypted).decode('utf-8')
                except Exception as e:
                    self.logger.log(url, f"加密失败: {str(e)}")
                    raise
        except Exception as e:
            self.logger.log(url, f"{'加密' if self.mode == 'encrypt' else '解密'}失败: {str(e)}")
            raise

    def process_form_data(self, form_data: str, url: str = None) -> tuple[str, bool]:
        """处理表单数据"""
        try:
            # 尝试解码表单数据
            if isinstance(form_data, bytes):
                form_data = form_data.decode('utf-8', errors='replace')
            
            params = parse_qs(form_data, keep_blank_values=True)
            modified = False
            new_params = {}

            # 保持所有原始字段，去掉列表形式
            for key, value in params.items():
                # 获取列表中的第一个值，如果没有则为空字符串
                value_str = value[0] if value else ''
                if key in self.decryption_fields and value_str:  # 只处理需要加解密的字段，且值不为空
                    try:
                        # 处理字段值
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
                # 构建原始表单数据字符串
                original_form = '&'.join(f"{k}={v}" for k, v in params.items() for v in [v[0] if v else ''])
                # 构建处理后的表单数据字符串
                processed_form = '&'.join(f"{k}={v}" for k, v in new_params.items())
                
                self.logger.log(url, self.logger._format_log_message(
                    url,
                    ','.join(self.decryption_fields),
                    original_form,  # 使用原始表单数据
                    processed_form,  # 使用处理后的表单数据
                    self.mode
                ))

            return urlencode(new_params, quote_via=quote), modified
        except Exception as e:
            self.logger.log(url, f"处理表单数据失败: {str(e)}")
            return form_data, False  # 如果处理失败，返回原始数据

    def process_json_data(self, json_data: dict, url: str = None) -> tuple[dict, bool]:
        modified = False
        new_data = {}

        for key, value in json_data.items():
            if key in self.decryption_fields:
                try:
                    if self.mode == 'encrypt':
                        value_str = json.dumps(value, separators=(',', ':'), ensure_ascii=False)
                        result = self.process_value(value_str, url, key)
                        new_data[key] = result
                    else:
                        if isinstance(value, str):
                            result = self.process_value(value, url, key)
                            try:
                                obj = json.loads(result)
                                new_data[key] = obj
                            except Exception:
                                new_data[key] = result
                        else:
                            new_data[key] = value
                    modified = True
                except Exception as e:
                    self.logger.log(url, f"处理失败: {str(e)}")
                    new_data[key] = value
            else:
                new_data[key] = value

        if modified:
            original_json = json.dumps(json_data, separators=(',', ':'), ensure_ascii=False)
            processed_json = json.dumps(new_data, separators=(',', ':'), ensure_ascii=False)
            self.logger.log(url, self.logger._format_log_message(
                url,
                ','.join(self.decryption_fields),
                original_json,
                processed_json,
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
key, iv = get_aes_config()

# 注册插件
addons = [AesCbcBothInterceptor(fields, key, iv)] 