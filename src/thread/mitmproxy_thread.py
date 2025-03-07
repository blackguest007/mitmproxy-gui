import os
import re
import subprocess
import traceback

from PyQt6.QtCore import QThread, pyqtSignal


class MitmProxyThread(QThread):
    new_log = pyqtSignal(str)  # 用于发送日志消息的信号
    new_packet = pyqtSignal(list)  # 用于发送数据包字段信息的信号

    def __init__(self, listen_port=None, command=None):
        super().__init__()
        self.log = ''  # 存储日志信息
        self.listen_port = listen_port  # 监听端口
        self.command = command  # 自定义命令
        self.process = None  # 存储子进程
        self.running = False  # 线程运行状态
        self.script_dir = os.path.dirname(os.path.abspath(__file__))  # 获取当前脚本目录
        self.script_path = os.path.join(self.script_dir, "..", "network", "mitmproxy_packet_capture.py")  # 默认抓包脚本路径

    def parse_http_request(self, raw_request):
        """解析HTTP请求，提取需要的信息"""
        try:
            # 分割请求行和请求头
            lines = raw_request.split('\n')
            request_line = lines[0].strip()

            # 解析请求行
            method, url, _ = request_line.split(' ')

            # 解析请求头
            headers = {}
            for line in lines[1:]:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

            # 获取当前时间
            from datetime import datetime
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # 构造表格行数据
            row_data = [
                current_time,  # 时间
                "Request",  # 类型
                "->",  # 方向
                method,  # 方法
                url,  # URL
                "200",  # 状态码（默认200）
                headers.get('Content-Length', '')  # 内容长度
            ]

            # 添加原始请求数据作为第8个元素
            row_data.append(raw_request)

            return row_data

        except Exception as e:
            print(f"Error parsing request: {e}")
            return None

    def run(self):
        """线程运行逻辑"""
        try:
            # 如果传入命令，则使用自定义命令
            if self.command:
                print(f"Starting process with command: {self.command}")
                self.process = subprocess.Popen(
                    self.command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8"
                )
            else:
                # 使用默认的抓包脚本
                command = ["mitmdump", "-p", str(self.listen_port), "-s", self.script_path, "--ssl-insecure"]
                print(f"Starting process with command: {command}")
                self.process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8"
                )

            if self.process is None:
                self.new_log.emit("❌ 无法启动 mitmdump 进程。")
                return

            self.running = True  # 设置运行状态为 True
            while self.running:
                if self.process.poll() is not None:
                    # 进程已经终止
                    error = self.process.stderr.read()  # 读取错误信息
                    if error:
                        self.new_log.emit(f"❌ 进程错误: {error}")
                    break

                line = self.process.stdout.readline()  # 读取标准输出
                if line:
                    if "error while attempting to bind on address" in line:
                        self.new_log.emit("❌ 端口被占用，请尝试其他端口或关闭占用端口的程序")
                        self.stop()  # 停止线程
                        break

                    self.log += line  # 累加日志
                    self.new_log.emit(line.strip())  # 发送日志消息
                    
                    # Default 模式下解析数据包
                    if not self.command:  # 只在 Default 模式下解析数据包
                        match = re.search(r"flow_start\n(.*?)\nflow_end", self.log, re.DOTALL)
                        if match:
                            full_flow_str = match.group(1)
                            try:
                                full_flow = eval(full_flow_str)  # 解析流数据
                                raw_request = full_flow.get('raw', '')

                                # 解析请求并发送新信号
                                row_data = self.parse_http_request(raw_request)
                                if row_data:
                                    print(f"Sending packet data: {row_data}")  # 调试输出
                                    self.new_packet.emit(row_data)  # 发送数据包信息

                            except Exception as e:
                                print(f"Error processing flow: {e}")

                            self.log = ''  # 清空日志

                self.msleep(100)  # 暂停100毫秒

        except Exception as e:
            self.new_log.emit(f"❌ 线程错误: {str(e)}")
            traceback.print_exc()  # 打印异常堆栈
        finally:
            self.cleanup()  # 清理资源

    def stop(self):
        """安全地停止线程和进程"""
        self.running = False  # 设置运行状态为 False
        if self.process:
            self.process.terminate()  # 尝试正常终止进程
            try:
                self.process.wait(timeout=3)  # 等待进程结束
            except subprocess.TimeoutExpired:
                self.process.kill()  # 强制结束进程
        print("Thread stopped.")  # 调试信息
        self.quit()  # 退出线程

    def cleanup(self):
        """清理资源"""
        try:
            if self.process:
                # 尝试正常终止进程
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    # 如果进程没有及时响应，强制结束它
                    self.process.kill()
                    self.process.wait()
                finally:
                    self.process = None  # 清空进程引用
        except Exception as e:
            print(f"清理资源时出错: {e}")
        finally:
            self.quit()  # 退出线程

