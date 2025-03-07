# path:/src/network/mitmproxy_packet_capture.py


import logging
from mitmproxy import http
from shard import *  # 假设你已经正确配置了共享数据结构，如 packet_queue

logging.basicConfig(level=logging.INFO)


class MyAddon():
    def __init__(self):
        self.active_flows = {}

    def request(self, flow: http.HTTPFlow) -> None:
        try:
            # 在MyAddon的request方法首行添加
            print(f"🔥 Intercepted: {flow.request.url}")

            # 构建类似Burp的请求格式
            raw_request = (
                f"{flow.request.method} {flow.request.url} {flow.request.http_version}\n"
                f"{self.format_headers(flow.request.headers)}\n\n"  # 格式化请求头
                f"{flow.request.text}"  # 请求体（如果有的话）
            )

            # 只传递必要元数据，不要传递flow对象
            packet_queue.put({
                "flow_id": id(flow),
                "raw": raw_request,
                "meta": {  # 添加可序列化元数据
                    "host": flow.request.host,
                    "port": flow.request.port,
                    "scheme": flow.request.scheme
                }
            })
            # 输出队列信息
            logging.info(f"flow_start\n{packet_queue.get()}\nflow_end")  # 格式化输出抓到的请求

        except Exception as e:
            logging.error(f"Error capturing request: {str(e)}")

    def format_headers(self, headers):
        """格式化请求头为类似Burp的格式"""
        formatted_headers = ""
        for header, value in headers.items():
            formatted_headers += f"{header}: {value}\n"
        return formatted_headers


# 注册插件
addons = [MyAddon()]
