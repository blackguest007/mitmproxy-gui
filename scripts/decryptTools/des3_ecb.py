"""
3DES-ECB 解密脚本

使用方法:
    mitmdump -p 8888 -s des3_ecb.py --ssl-insecure field=password key=your_3des_key
    mitmdump -p 8888 -s des3_ecb.py --ssl-insecure field=password,username key=your_3des_key

参数说明:
    -p 8888: 监听端口
    -s des3_ecb.py: 指定脚本文件
    --ssl-insecure: 忽略 SSL 证书验证
    field=password: 单个解密字段
    field=password,username: 多个解密字段，用逗号分隔
    key=your_3des_key: 3DES密钥(24字节)

注意事项:
    1. 支持 application/json 和 application/x-www-form-urlencoded 格式
    2. 支持单个或多个字段解密
    3. 需要提供3DES密钥
    4. 解密前的数据需要是Base64编码
"""

import sys
from mitmproxy import http
from mitmproxy.script import concurrent
import json
from urllib.parse import parse_qs, urlencode
import threading
import queue
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
import os
from datetime import datetime
from Crypto.Cipher import DES3
from Crypto.Util.Padding import unpad
import base64
from typing import List, Tuple, Dict, Any

def get_decryption_config():
    """从命令行参数获取解密配置"""
    all_args = sys.argv
    decryption_fields = []
    des3_key = None

    for arg in all_args:
        if arg.startswith('field='):
            fields = arg.replace('field=', '')
            decryption_fields = [field.strip() for field in fields.split(',') if field.strip()]
        elif arg.startswith('key='):
            des3_key = arg.replace('key=', '').strip()

    return decryption_fields, des3_key

# 获取解密配置
decryption_fields, des3_key = get_decryption_config()

class AsyncLogger:
    """异步日志处理器"""
    def __init__(self, decryption_fields: List[str]):
        self.log_queue = queue.Queue()
        self.running = True
        self.thread = threading.Thread(target=self._process_logs, daemon=True)
        self.thread.start()
        
        # 创建日志目录
        self.log_dir = "logs"
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            
        # 创建日志文件
        self.log_file = os.path.join(self.log_dir, f"decrypt_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        
        # 用于显示的最近日志
        self.recent_logs = []
        self.max_recent_logs = 50
        
        # 检查是否在mitmdump模式下运行
        self.is_mitmdump = 'mitmdump' in sys.argv[0]

        self.decryption_fields = decryption_fields

    def _format_log_message(self, url: str, field: str, original: str, processed: str) -> str:
        """格式化日志消息"""
        return f"URL: {url} | 字段: {field} | 原始值: {original} | 解密值: {processed}"

    def _process_logs(self):
        """处理日志队列"""
        while self.running:
            try:
                # 非阻塞方式获取日志
                log_entry = self.log_queue.get_nowait()
                if log_entry:
                    flow, comment = log_entry
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    log_message = f"[{timestamp}] {comment}"
                    
                    # 保存到文件
                    with open(self.log_file, 'a', encoding='utf-8') as f:
                        f.write(log_message + '\n')
                    
                    # 更新最近日志
                    self.recent_logs.append(log_message)
                    if len(self.recent_logs) > self.max_recent_logs:
                        self.recent_logs.pop(0)
                    
                    # 在mitmdump模式下打印到控制台
                    if self.is_mitmdump:
                        print(f"\n{log_message}")
                    else:
                        # 在GUI中显示
                        flow.request.comment = '\n'.join(self.recent_logs)
                    
            except queue.Empty:
                # 队列为空时短暂休眠
                time.sleep(0.1)
            except Exception:
                pass

    def log(self, flow, comment):
        """添加日志到队列"""
        try:
            self.log_queue.put_nowait((flow, comment))
        except queue.Full:
            # 队列满时丢弃最旧的日志
            try:
                self.log_queue.get_nowait()
                self.log_queue.put_nowait((flow, comment))
            except:
                pass

    def stop(self):
        """停止日志处理"""
        self.running = False
        self.thread.join()

class Des3EcbDecryptInterceptor:
    """DES3-ECB 解密拦截器"""
    
    def __init__(self, decryption_fields: List[str], key: str):
        self.decryption_fields = decryption_fields
        self.key = key.encode('utf-8')
        self._lock = threading.Lock()
        self.logger = AsyncLogger(decryption_fields)
        self._initialized = True  # 添加初始化标志

    def decrypt_value(self, encrypted_text: str, url: str, field: str) -> str:
        """解密单个值"""
        if not hasattr(self, '_initialized'):  # 检查是否已初始化
            return encrypted_text
        
        try:
            # 创建新的cipher实例
            cipher = DES3.new(self.key, DES3.MODE_ECB)
            
            # 解密数据
            encrypted_data = base64.b64decode(encrypted_text)
            decrypted_data = cipher.decrypt(encrypted_data)
            unpadded_data = unpad(decrypted_data, DES3.block_size)
            decrypted_text = unpadded_data.decode('utf-8')
            
            return decrypted_text
        except Exception as e:
            error_msg = f"解密失败: {str(e)}"
            raise

    def _get_request_url(self, flow: http.HTTPFlow) -> str:
        return f"{flow.request.scheme}://{flow.request.host}{flow.request.path}"

    @concurrent
    def request(self, flow: http.HTTPFlow) -> None:
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

    def done(self) -> None:
        """脚本退出时的清理函数"""
        global STOP_EVENT
        STOP_EVENT.set()
        self.logger.stop()

# 注册插件
addons = [Des3EcbDecryptInterceptor(decryption_fields, des3_key)] 