"""
基础拦截器模块

提供通用的数据包处理逻辑，包括：
1. JSON 数据处理
2. 表单数据处理
3. 请求处理流程
4. 并发支持
5. 日志记录
6. 配置管理
7. 错误处理
8. 数据包处理

使用方式：
    继承该类并实现 process_func 方法，用于处理具体的加密/解密逻辑
    例如：
    class MyInterceptor(BaseInterceptor):
        def __init__(self):
            super().__init__(
                script_name="my_script",
                mode="decrypt",
                processing_fields=["password"],
                process_func=self.my_process_func
            )
"""

from mitmproxy import http
from mitmproxy.script import concurrent
import json
from urllib.parse import parse_qs, urlencode
from typing import Dict, Any, Tuple, List, Callable, Union
from .logger import PacketLogger

class BaseInterceptor:
    """
    基础拦截器类
    
    所有拦截器都继承自该类，提供通用的数据包处理功能。
    包括JSON和表单数据的处理、并发支持、日志记录等。
    
    Attributes:
        processing_fields (List[str]): 需要处理的字段列表
        logger (PacketLogger): 日志记录器实例
        process_func (Callable): 处理函数，用于处理字段值
    """
    
    def __init__(self, script_name: str, mode: str, processing_fields: List[str], process_func: Callable[[str, str, str, Dict[str, Any], str], str]):
        """
        初始化拦截器
        
        Args:
            script_name (str): 脚本名称，用于日志文件名
            mode (str): 处理模式，可选值：
                       - "encrypt": 加密模式
                       - "decrypt": 解密模式
                       - "both": 同时支持加密和解密
            processing_fields (List[str]): 需要处理的字段列表
                                         例如: ["password", "username"]
            process_func (Callable): 处理函数，用于处理字段值
                                   函数签名: (value: str, url: str, field: str, 
                                           full_json: Dict[str, Any], form_data: str) -> str
        """
        self.processing_fields = processing_fields
        self.logger = PacketLogger(script_name, mode)
        self.logger.fields = processing_fields
        self.process_func = process_func

    def process_json_data(self, data: Dict[str, Any], url: str, is_response: bool = False) -> Tuple[Dict[str, Any], bool]:
        """处理JSON数据"""
        modified = False
        original_data = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
        
        for field in self.processing_fields:
            if field in data and isinstance(data[field], str):
                try:
                    original_value = data[field]
                    processed_value = self.process_func(original_value, url, field, data)
                    if processed_value and processed_value != original_value:
                        data[field] = processed_value
                        modified = True
                except Exception as e:
                    self.logger.log(None, f"处理字段 {field} 失败: {str(e)}")
                    continue
        
        if modified:
            final_data = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
            self.logger.log(None, self.logger._format_log_message(url, field, original_data, final_data, is_response=is_response))
                    
        return data, modified

    def process_form_data(self, form_data: str, url: str, is_response: bool = False) -> Tuple[str, bool]:
        """处理表单数据"""
        try:
            # 解析表单数据，保持原始格式
            parsed_data = {}
            for pair in form_data.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    parsed_data[key] = [value]
            
            modified = False
            original_values = {}  # 存储原始值
            
            for field in self.processing_fields:
                if field in parsed_data:
                    try:
                        value = parsed_data[field][0]
                        # 保存原始值，不进行任何处理
                        original_values[field] = value
                        # 处理值，确保没有引号
                        processed_value = self.process_func(value.strip('"').strip("'"), url, field, form_data=form_data)
                        if processed_value and processed_value != value:
                            parsed_data[field] = [processed_value]
                            modified = True
                    except Exception as e:
                        self.logger.log(None, f"处理字段 {field} 失败: {str(e)}")
                        continue
            
            if modified:
                # 构建新的表单数据，不进行URL编码
                new_parts = []
                for k, v in parsed_data.items():
                    if isinstance(v, list):
                        new_parts.append(f"{k}={v[0]}")
                    else:
                        new_parts.append(f"{k}={v}")
                new_content = "&".join(new_parts)
                
                # 记录日志，使用完整的表单数据
                self.logger.log(None, self.logger._format_log_message(
                    url,
                    field,
                    form_data,  # 使用完整的表单数据作为原始值
                    new_content,  # 使用完整的处理后表单数据
                    is_response=is_response
                ))
                
                return new_content, True
                
            return form_data, False
            
        except Exception as e:
            self.logger.log(None, f"处理表单数据失败: {str(e)}")
            return form_data, False

    @concurrent
    def request(self, flow: http.HTTPFlow) -> None:
        """处理请求"""
        if not flow.request.content:
            return

        content_type = flow.request.headers.get("Content-Type", "")
        url = f"{flow.request.scheme}://{flow.request.host}{flow.request.path}"

        try:
            if "application/json" in content_type:
                try:
                    json_data = json.loads(flow.request.content)
                    json_data, modified = self.process_json_data(json_data, url, is_response=False)
                    if modified:
                        flow.request.content = json.dumps(json_data, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
                        flow.request.headers["Content-Length"] = str(len(flow.request.content))
                except json.JSONDecodeError as e:
                    self.logger.log(None, f"JSON解析失败: {str(e)}")
                    return

            elif "application/x-www-form-urlencoded" in content_type:
                try:
                    form_data = flow.request.content.decode('utf-8')
                    new_content, modified = self.process_form_data(form_data, url, is_response=False)
                    if modified:
                        flow.request.content = new_content.encode('utf-8')
                        flow.request.headers["Content-Length"] = str(len(flow.request.content))
                except UnicodeDecodeError as e:
                    self.logger.log(None, f"表单数据解码失败: {str(e)}")
                    return

        except Exception as e:
            self.logger.log(None, f"请求处理失败: {str(e)}")

    @concurrent
    def response(self, flow: http.HTTPFlow) -> None:
        """处理响应"""
        if not flow.response or not flow.response.content:
            return
            
        content_type = flow.response.headers.get("Content-Type", "")
        url = f"{flow.request.scheme}://{flow.request.host}{flow.request.path}"

        try:
            # 获取响应内容
            content = flow.response.content.decode('utf-8')
            
            # 处理 JSON 数据
            if "application/json" in content_type:
                try:
                    json_data = json.loads(content)
                    json_data, modified = self.process_json_data(json_data, url, is_response=True)
                    if modified:
                        flow.response.content = json.dumps(json_data, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
                        flow.response.headers["Content-Length"] = str(len(flow.response.content))
                except json.JSONDecodeError as e:
                    self.logger.log(None, f"响应JSON解析失败: {str(e)}")
                    return

            # 处理表单数据
            elif "application/x-www-form-urlencoded" in content_type:
                try:
                    new_content, modified = self.process_form_data(content, url, is_response=True)
                    if modified:
                        flow.response.content = new_content.encode('utf-8')
                        flow.response.headers["Content-Length"] = str(len(flow.response.content))
                except UnicodeDecodeError as e:
                    self.logger.log(None, f"响应表单数据解码失败: {str(e)}")
                    return
                    
            # 处理其他类型的数据（如 text/html）
            else:
                # 记录原始响应内容
                self.logger.log(None, self.logger._format_log_message(url, 'response', content, content, is_response=True))

        except Exception as e:
            self.logger.log(None, f"响应处理失败: {str(e)}")

    def done(self) -> None:
        """脚本结束时调用"""
        pass 