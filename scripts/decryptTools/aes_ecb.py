"""
AES-ECB 解密脚本

使用方法:
    mitmdump -p 8888 -s aes_ecb.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password key=1234567890123456
    mitmdump -p 8888 -s aes_ecb.py --mode upstream:http://127.0.0.1:8080 --ssl-insecure field=password,username key=1234567890123456

参数说明:
    -p 8888: 监听端口
    -s aes_ecb.py: 指定脚本文件
    --mode upstream:http://127.0.0.1:8080: 指定代理服务器
    --ssl-insecure: 忽略 SSL 证书验证
    field=password: 单个解密字段
    field=password,username: 多个解密字段，用逗号分隔
    key=1234567890123456: AES密钥，必须是16/24/32字节

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段解密
    3. AES密钥必须是16/24/32字节长度
    4. 解密前的数据需要是Base64编码
    5. 日志文件保存在 logs 目录下，格式为: aes_ecb_字段名_时间戳.log
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
from Crypto.Cipher import AES
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

# 包计数器
_packet_counter = 0
_packet_counter_lock = threading.Lock()

def get_packet_number(url: str, content: str) -> int:
    """获取包序号"""
    global _packet_counter
    with _packet_counter_lock:
        _packet_counter += 1
        return _packet_counter

def get_decryption_config() -> Tuple[List[str], str]:
    """从命令行参数获取解密配置"""
    decryption_fields = []
    key = None

    for arg in sys.argv:
        if arg.startswith('field='):
            fields = arg.replace('field=', '')
            decryption_fields = [field.strip() for field in fields.split(',') if field.strip()]
        elif arg.startswith('key='):
            key = arg.replace('key=', '').strip()

    if not decryption_fields:
        decryption_fields = ['password']  # 默认解密字段
    if not key:
        raise ValueError("必须提供 key 参数")
    if len(key.encode('utf-8')) not in [16, 24, 32]:
        raise ValueError("AES密钥必须是16/24/32字节长度")

    return decryption_fields, key

def get_log_filename(fields: List[str]) -> str:
    """生成日志文件名"""
    return f"aes_ecb_{'_'.join(fields)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

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

# 获取解密配置
try:
    decryption_fields, key = get_decryption_config()
except Exception as e:
    print(f"参数错误: {e}", file=sys.stderr)
    sys.exit(1)

# 初始化日志处理器
logger = AsyncLogger()

class AesEcbDecryptInterceptor:
    """AES-ECB 解密拦截器"""
    
    def __init__(self, decryption_fields: List[str], key: str):
        self.decryption_fields = decryption_fields
        self.key = key.encode('utf-8')
        self._lock = threading.Lock()
        self.logger = AsyncLogger()
        self._initialized = True  # 添加初始化标志
        print(f"初始化成功，监听字段: {decryption_fields}, 密钥长度: {len(key)}")  # 添加初始化日志

    def decrypt_value(self, encrypted_text: str, url: str, field: str, full_json: Dict[str, Any] = None, form_data: str = "") -> str:
        """解密单个值"""
        if not hasattr(self, '_initialized'):  # 检查是否已初始化
            return encrypted_text
            
        try:
            # 创建新的cipher实例
            cipher = AES.new(self.key, AES.MODE_ECB)
            
            # 解密数据
            encrypted_data = base64.b64decode(encrypted_text)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            decrypted_text = decrypted_data.decode('utf-8')
            
            return decrypted_text
        except Exception as e:
            error_msg = f"解密失败: {str(e)}"
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
                    # 记录原始值
                    original_value = data[field]
                    # 解密
                    decrypted_value = self.decrypt_value(original_value, url, field)
                    try:
                        # 尝试将解密后的值解析为JSON
                        data[field] = json.loads(decrypted_value)
                    except json.JSONDecodeError:
                        data[field] = decrypted_value
                    modified = True
                except Exception as e:
                    # 解密失败时已经在decrypt_value中记录了日志
                    continue
        
        # 只在数据被修改时记录日志，并且只记录最终的解密结果
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
            
            for field in self.decryption_fields:
                if field in parsed_data:
                    try:
                        value = parsed_data[field][0]
                        decrypted_value = self.decrypt_value(value, url, field, form_data=form_data)
                        parsed_data[field] = [decrypted_value]
                        modified = True
                    except Exception as e:
                        # 解密失败时已经在decrypt_value中记录了日志
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
        if STOP_EVENT.is_set():
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
                        error_msg = f"JSON解析失败: {str(e)}"
                        self.logger.log(None, self.logger._format_log_message(url, "", str(flow.request.content), error_msg))
                        return

                elif "application/x-www-form-urlencoded" in content_type:
                    try:
                        form_data = flow.request.content.decode('utf-8')
                        new_content, modified = self.process_form_data(form_data, url)
                        if modified:
                            flow.request.content = new_content.encode('utf-8')
                            flow.request.headers["Content-Length"] = str(len(flow.request.content))
                    except UnicodeDecodeError as e:
                        error_msg = f"表单数据解码失败: {str(e)}"
                        self.logger.log(None, self.logger._format_log_message(url, "", str(flow.request.content), error_msg))
                        return

        except Exception as e:
            error_msg = f"请求处理失败: {str(e)}"
            self.logger.log(None, self.logger._format_log_message(url, "", str(flow.request.content), error_msg))

    def _get_request_url(self, flow: http.HTTPFlow) -> str:
        """获取请求URL"""
        return f"{flow.request.scheme}://{flow.request.host}{flow.request.path}"

    def done(self) -> None:
        """脚本退出时的清理函数"""
        global STOP_EVENT
        STOP_EVENT.set()
        self.logger.stop()

# 注册插件
addons = [AesEcbDecryptInterceptor(decryption_fields, key)]