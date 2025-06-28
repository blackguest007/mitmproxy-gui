"""
数据包处理日志模块

提供统一的日志处理功能，包括：
1. 异步日志处理
2. 日志格式化
3. 日志文件管理
4. 数据包序号管理
"""

import threading
import queue
import time
import os
from datetime import datetime
from typing import Dict, Any, Optional
from urllib.parse import parse_qs, urlencode
import json

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

class PacketLogger:
    """数据包处理异步日志处理器"""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(PacketLogger, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, script_name: str, mode: str = "decrypt"):
        """
        初始化日志处理器
        
        Args:
            script_name: 脚本名称
            mode: 处理模式，可选值：encrypt（加密）、decrypt（解密）、both（双向）
        """
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
            current_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            self.log_dir = os.path.join(current_dir, "src", "logs")
            if not os.path.exists(self.log_dir):
                try:
                    os.makedirs(self.log_dir)
                    print(f"创建日志目录: {self.log_dir}")
                except Exception as e:
                    print(f"创建日志目录失败: {str(e)}")
                    self.log_dir = os.path.join(os.getcwd(), "logs")
                    if not os.path.exists(self.log_dir):
                        os.makedirs(self.log_dir)
                    print(f"使用备用日志目录: {self.log_dir}")
                
            # 创建日志文件
            self.log_file = os.path.join(self.log_dir, f"{mode}_{script_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
            print(f"日志文件路径: {self.log_file}")
            self._initialized = True
            self.fields = []  # 初始化字段列表
            self.last_flush_time = time.time()  # 添加最后刷新时间记录
            self.mode = mode  # 保存处理模式

    def _format_log_message(self, url: str, field: str, original: str, processed: str, full_json: Dict[str, Any] = None, form_data: str = "", is_response: bool = False) -> str:
        """格式化日志消息"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]  # 添加毫秒
        packet_number = get_packet_number(url, original)
        direction = "响应" if is_response else "请求"
        
        # 如果是表单数据，直接显示原始值
        if form_data:
            return (
                f"[{timestamp}] #{packet_number} URL: {url}\n"
                f"方向: {direction}\n"
                f"模式: {self.mode}\n"
                f"字段: {field}\n"
                f"原始值: {form_data}\n"  # 记录完整的表单数据
                f"处理值: {field}={processed}\n"  # 记录处理后的表单数据
                f"{'='*50}\n\n"  # 添加两个换行符
            )
        
        # 如果是JSON数据，保持原始格式
        try:
            if isinstance(original, str):
                original_json = json.loads(original)
                original = json.dumps(original_json, ensure_ascii=False, separators=(',', ':'))
            if isinstance(processed, str):
                processed_json = json.loads(processed)
                # 如果是嵌套的JSON字符串，先解析内层
                if isinstance(processed_json.get(field), str):
                    try:
                        inner_json = json.loads(processed_json[field])
                        processed_json[field] = inner_json
                    except:
                        pass
                processed = json.dumps(processed_json, ensure_ascii=False, separators=(',', ':'))
        except:
            pass
            
        return (
            f"[{timestamp}] #{packet_number} URL: {url}\n"
            f"方向: {direction}\n"
            f"模式: {self.mode}\n"
            f"字段: {field}\n"
            f"原始值: {original}\n"
            f"处理值: {processed}\n"
            f"{'='*50}\n\n"  # 添加两个换行符
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
                        f.write(comment)  # 不添加额外的换行符，因为已经在格式化时添加了
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
                    f.write(comment)  # 不添加额外的换行符，因为已经在格式化时添加了
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