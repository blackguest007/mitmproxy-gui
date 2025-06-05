"""
RSA 解密脚本-已测试√√

使用方法:
    mitmdump -p 8888 -s rsa.py --ssl-insecure field=password private_key=path/to/private.pem

参数说明:
    field: 需要处理的字段，多个字段用逗号分隔
    private_key: RSA私钥文件路径

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段处理
    3. 私钥文件必须是有效的 PEM 格式
    4. 解密前的数据需要是Base64编码
    5. 使用 PKCS1_v1_5 填充模式，与 jsencrypt.js 库保持一致
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
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

# 全局停止标志
STOP_EVENT = threading.Event()

# 日志配置
LOG_CONFIG = {
    'batch_size': 50,  # 批处理大小
    'flush_interval': 1.0,  # 文件刷新间隔（秒）
    'queue_timeout': 0.1,  # 队列获取超时时间
    'sleep_interval': 0.01,  # 空闲时睡眠时间
}

def get_decryption_config() -> Tuple[List[str], str]:
    """从命令行参数获取解密配置"""
    decryption_fields = []
    private_key_path = None

    for arg in sys.argv:
        if arg.startswith('field='):
            fields = arg.replace('field=', '')
            decryption_fields = [field.strip() for field in fields.split(',') if field.strip()]
        elif arg.startswith('private_key='):
            private_key_path = arg.replace('private_key=', '').strip()
    
    if not decryption_fields:
        decryption_fields = ['password']  # 默认解密字段
    if not private_key_path:
        raise ValueError("必须提供 private_key 参数")
    if not os.path.exists(private_key_path):
        raise ValueError(f"私钥文件不存在: {private_key_path}")

    return decryption_fields, private_key_path

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
        return (
            f"[{timestamp}] URL: {url}\n"
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
    decryption_fields, private_key_path = get_decryption_config()
except Exception as e:
    print(f"参数错误: {e}", file=sys.stderr)
    sys.exit(1)

# 初始化日志处理器
logger = AsyncLogger()

class RsaDecryptInterceptor:
    """RSA 解密拦截器"""
    
    def __init__(self, decryption_fields: List[str], private_key_path: str):
        self.decryption_fields = decryption_fields
        self._lock = threading.Lock()
        self.logger = AsyncLogger()  # 使用单例模式
        self._initialized = True  # 添加初始化标志
        
        # 读取私钥文件
        try:
            with open(private_key_path, 'r') as f:
                self.private_key = RSA.import_key(f.read())
        except Exception as e:
            raise ValueError(f"读取私钥文件失败: {str(e)}")

    def decrypt_value(self, encrypted_text: str, url: str, field: str) -> str:
        """解密单个值"""
        if not hasattr(self, '_initialized'):  # 检查是否已初始化
            return encrypted_text
            
        try:
            # 创建新的cipher实例
            cipher = PKCS1_v1_5.new(self.private_key)
            
            # 解密数据
            encrypted_data = base64.b64decode(encrypted_text)
            decrypted_data = cipher.decrypt(encrypted_data, None)
            plain_text = decrypted_data.decode('utf-8')
            
            return plain_text
        except Exception as e:
            error_msg = f"解密失败: {str(e)}"
            raise

    def _get_request_url(self, flow: http.HTTPFlow) -> str:
        """获取请求URL"""
        return f"{flow.request.scheme}://{flow.request.host}{flow.request.path}"

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
                        original_encrypted,
                        decrypted_value
                    ))
                except Exception as e:
                    # 记录解密失败
                    self.logger.log(None, self.logger._format_log_message(
                        url,
                        field,
                        data[field],
                        f"解密失败: {str(e)}"
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
                        # 构建包含所有字段的表单数据
                        result_data = []
                        for k, v in parsed_data.items():
                            if k == field:
                                result_data.append(f"{k}={decrypted_value}")
                            else:
                                result_data.append(f"{k}={v[0]}")
                        result_form = "&".join(result_data)
                        
                        self.logger.log(None, self.logger._format_log_message(
                            url,
                            field,
                            form_data,  # 原始完整表单数据
                            result_form  # 解密后的完整表单数据
                        ))
                    except Exception as e:
                        # 记录解密失败
                        self.logger.log(None, self.logger._format_log_message(
                            url,
                            field,
                            form_data,  # 原始完整表单数据
                            f"解密失败: {str(e)}"
                        ))
                        continue
            
            if modified:
                return urlencode(parsed_data, doseq=True), True
            return form_data, False
            
        except Exception as e:
            error_msg = f"处理表单数据失败: {str(e)}"
            self.logger.log(None, self.logger._format_log_message(url, "", form_data, error_msg))
            return form_data, False

    def done(self) -> None:
        """脚本退出时的清理函数"""
        global STOP_EVENT
        STOP_EVENT.set()
        self.logger.stop()

# 注册插件
addons = [RsaDecryptInterceptor(decryption_fields, private_key_path)]