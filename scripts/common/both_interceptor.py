"""
Both 模式专用基类

提供双向加解密功能，支持：
1. 请求处理（使用指定模式）
2. 响应处理（使用相反模式）
3. 完整的日志记录
4. 错误处理

使用方式：
    继承该类并实现 process_value 方法
    
工作原理：
    Both 模式实现完整的双向代理链：
    
    请求阶段：浏览器 → Burp(密文) → mitmproxy(解密) → 服务器(明文)
    响应阶段：服务器(明文) → mitmproxy(加密) → Burp(密文) → 浏览器(明文)
    
    这样可以让 Burp 看到明文数据，便于分析和测试
"""

from mitmproxy import http
from mitmproxy.script import concurrent
import json
from urllib.parse import parse_qs, urlencode
from typing import Dict, Any, List
from .logger import PacketLogger

class BothInterceptor:
    """Both 模式专用基类"""
    
    def __init__(self, script_name: str, mode: str, processing_fields: List[str]):
        """
        初始化 Both 模式拦截器
        
        Args:
            script_name: 脚本名称，用于日志文件名（如：aes_cbc, base64）
            mode: 基础模式（'encrypt' 或 'decrypt'）
                  - decrypt: 请求解密，响应加密（常用）
                  - encrypt: 请求加密，响应解密
            processing_fields: 需要处理的字段列表（如：['password', 'token']）
        """
        self.processing_fields = processing_fields  # 存储要处理的字段名列表
        self.mode = mode  # 存储基础模式
        self.logger = PacketLogger(script_name, "both")  # 创建日志记录器
        self.logger.fields = processing_fields  # 设置日志记录的字段

    def process_value(self, value: str, url: str, field: str, is_response: bool = False) -> str:
        """
        处理单个字段的值 - 子类必须实现此方法
        
        Args:
            value: 要处理的值（字段的原始值）
            url: 请求URL（用于日志记录）
            field: 字段名（如：password, token）
            is_response: 是否为响应数据
                        - False: 请求数据，使用基础模式
                        - True: 响应数据，使用相反模式
            
        Returns:
            处理后的值
            
        注意：
            子类需要根据 is_response 参数决定是加密还是解密：
            - 如果基础模式是 decrypt：
              * 请求时（is_response=False）：解密
              * 响应时（is_response=True）：加密
            - 如果基础模式是 encrypt：
              * 请求时（is_response=False）：加密  
              * 响应时（is_response=True）：解密
        """
        raise NotImplementedError("子类必须实现 process_value 方法")

    def _process_json_data(self, data: Dict[str, Any], url: str, is_response: bool = False) -> tuple[Dict[str, Any], bool]:
        """
        处理JSON数据
        
        Args:
            data: 解析后的JSON数据字典
            url: 请求URL
            is_response: 是否为响应数据
            
        Returns:
            tuple: (处理后的数据字典, 是否有修改)
        """
        modified = False  # 标记是否有字段被修改
        
        # 遍历所有需要处理的字段
        for field in self.processing_fields:
            if field in data:  # 如果当前JSON中包含这个字段
                try:
                    original_value = data[field]
                    
                    # 借鉴 interceptor.py 的处理逻辑：统一处理不同类型的值
                    if not isinstance(original_value, str):
                        # 对象序列化为字符串
                        string_value = json.dumps(original_value, separators=(',', ':'), ensure_ascii=False)
                    else:
                        # 字符串尝试标准化格式
                        try:
                            obj = json.loads(original_value)
                            string_value = json.dumps(obj, separators=(',', ':'), ensure_ascii=False)
                        except Exception:
                            # 不是 JSON 字符串就原样处理
                            string_value = original_value
                    
                    # 调用子类实现的处理方法
                    processed_value = self.process_value(string_value, url, field, is_response)
                    
                    # 如果处理后的值发生了变化
                    if processed_value != string_value:
                        # 检查处理后的值是否是有效的JSON字符串
                        # 如果是，则解析为对象避免双重转义
                        final_value = processed_value
                        if isinstance(processed_value, str):
                            try:
                                # 尝试解析为JSON对象
                                parsed_json = json.loads(processed_value)
                                final_value = parsed_json
                            except json.JSONDecodeError:
                                # 不是有效JSON，保持为字符串
                                final_value = processed_value
                        
                        # 创建处理前后的完整JSON数据用于日志记录
                        original_data = data.copy()  # 处理前的完整数据
                        processed_data = data.copy()  # 处理后的完整数据
                        processed_data[field] = processed_value  # 日志中记录原始处理值
                        
                        # 更新实际的数据（使用解析后的值）
                        data[field] = final_value
                        modified = True  # 标记有修改
                        
                        # 记录成功处理的日志 - 传递完整的JSON数据
                        original_json = json.dumps(original_data, separators=(',', ':'), ensure_ascii=False)
                        processed_json = json.dumps(processed_data, separators=(',', ':'), ensure_ascii=False)
                        
                        # 格式化并记录日志
                        log_message = self.logger._format_log_message(
                            url, field, original_json, processed_json, 
                            full_json=data, is_response=is_response
                        )
                        self.logger.log(None, log_message)
                        
                except Exception as e:
                    # 如果处理某个字段失败，记录错误但继续处理其他字段
                    direction = '响应' if is_response else '请求'
                    self.logger.log(None, f"处理{direction}字段 {field} 失败: {str(e)}")
        
        return data, modified

    def _process_form_data(self, content: str, url: str, is_response: bool = False) -> tuple[str, bool]:
        """
        处理表单数据（application/x-www-form-urlencoded）
        
        Args:
            content: 原始表单数据字符串（如：username=admin&password=123）
            url: 请求URL
            is_response: 是否为响应数据
            
        Returns:
            tuple: (处理后的表单数据字符串, 是否有修改)
        """
        try:
            # 手动解析表单数据，避免URL编码问题（参考interceptor.py）
            parsed_data = {}
            for pair in content.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    parsed_data[key] = [value]
            
            modified = False  # 标记是否有修改
            
            # 遍历所有表单参数
            for key in self.processing_fields:
                if key in parsed_data:
                    try:
                        value_str = parsed_data[key][0] if parsed_data[key] else ''
                        
                        if value_str:
                            # 调用子类实现的处理方法
                            processed_value = self.process_value(value_str, url, key, is_response)
                            
                            # 如果处理后的值发生了变化
                            if processed_value != value_str:
                                parsed_data[key] = [processed_value]
                                modified = True  # 标记有修改
                                
                                # 记录成功处理的日志
                                # 手动构建处理前后的表单字符串（避免URL编码）
                                def build_form_string(data_dict):
                                    parts = []
                                    for k, v in data_dict.items():
                                        value = v[0] if v else ''
                                        parts.append(f"{k}={value}")
                                    return "&".join(parts)
                                
                                # 创建处理前后的数据副本用于日志
                                original_data = {k: v[:] for k, v in parsed_data.items()}
                                original_data[key] = [value_str]  # 恢复原始值
                                
                                original_form = build_form_string(original_data)
                                processed_form = build_form_string(parsed_data)
                                
                                # 记录日志
                                log_message = self.logger._format_log_message(
                                    url, key, original_form, processed_form, 
                                    form_data=content, is_response=is_response
                                )
                                self.logger.log(None, log_message)
                                
                    except Exception as e:
                        # 如果处理某个字段失败，记录错误但保留原值
                        direction = '响应' if is_response else '请求'
                        self.logger.log(None, f"处理{direction}表单字段 {key} 失败: {str(e)}")
            
            # 如果有字段被修改，手动构建新的表单字符串
            if modified:
                new_parts = []
                for k, v in parsed_data.items():
                    if isinstance(v, list):
                        new_parts.append(f"{k}={v[0]}")
                    else:
                        new_parts.append(f"{k}={v}")
                new_content = "&".join(new_parts)
                return new_content, True
            return content, False  # 没有修改，返回原内容
            
        except Exception as e:
            # 如果整个表单处理失败，记录错误并返回原内容
            direction = '响应' if is_response else '请求'
            self.logger.log(None, f"处理{direction}表单数据失败: {str(e)}")
            return content, False

    @concurrent
    def request(self, flow: http.HTTPFlow) -> None:
        """
        处理请求 - 使用基础模式
        
        在 both 模式中，这是第一步处理：
        - 如果基础模式是 decrypt：对请求数据进行解密
        - 如果基础模式是 encrypt：对请求数据进行加密
        
        Args:
            flow: mitmproxy 的 HTTP 流对象
        """
        # 如果请求没有内容，直接返回
        if not flow.request.content:
            return

        # 获取请求的内容类型和URL
        content_type = flow.request.headers.get("Content-Type", "")
        url = f"{flow.request.scheme}://{flow.request.host}{flow.request.path}"

        try:
            # 处理 JSON 格式的请求
            if "application/json" in content_type:
                try:
                    # 解码请求内容
                    content = flow.request.content.decode('utf-8')
                    json_data = json.loads(content)  # 解析JSON
                    
                    # 处理JSON数据（is_response=False 表示这是请求）
                    json_data, modified = self._process_json_data(json_data, url, is_response=False)
                    
                    # 如果数据被修改，更新请求内容
                    if modified:
                        # 将处理后的JSON重新编码为字节
                        flow.request.content = json.dumps(json_data, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
                        # 更新Content-Length头
                        flow.request.headers["Content-Length"] = str(len(flow.request.content))
                        
                except json.JSONDecodeError as e:
                    # JSON解析失败，记录错误
                    self.logger.log(None, f"请求JSON解析失败: {str(e)}")

            # 处理表单格式的请求
            elif "application/x-www-form-urlencoded" in content_type:
                try:
                    # 解码请求内容
                    content = flow.request.content.decode('utf-8')
                    
                    # 处理表单数据（is_response=False 表示这是请求）
                    new_content, modified = self._process_form_data(content, url, is_response=False)
                    
                    # 如果数据被修改，更新请求内容
                    if modified:
                        flow.request.content = new_content.encode('utf-8')
                        # 更新Content-Length头
                        flow.request.headers["Content-Length"] = str(len(flow.request.content))
                        
                except UnicodeDecodeError as e:
                    # 解码失败，记录错误
                    self.logger.log(None, f"请求表单数据解码失败: {str(e)}")

        except Exception as e:
            # 请求处理过程中的其他错误
            self.logger.log(None, f"请求处理失败: {str(e)}")

    @concurrent
    def response(self, flow: http.HTTPFlow) -> None:
        """
        处理响应 - 使用相反模式
        
        在 both 模式中，这是第二步处理：
        - 如果基础模式是 decrypt：对响应数据进行加密（相反操作）
        - 如果基础模式是 encrypt：对响应数据进行解密（相反操作）
        
        这样可以确保代理链的正确工作：
        浏览器 ←→ Burp(看到明文) ←→ mitmproxy(双向转换) ←→ 服务器
        
        Args:
            flow: mitmproxy 的 HTTP 流对象
        """
        # 如果响应不存在或没有内容，直接返回
        if not flow.response or not flow.response.content:
            return
            
        # 获取响应的内容类型和URL
        content_type = flow.response.headers.get("Content-Type", "")
        url = f"{flow.request.scheme}://{flow.request.host}{flow.request.path}"

        try:
            # 先获取响应内容
            content = flow.response.content.decode('utf-8')
            
            # 处理 JSON 格式的响应
            if "application/json" in content_type:
                try:
                    json_data = json.loads(content)  # 解析JSON
                    
                    # 检查JSON中是否包含需要处理的字段
                    has_target_fields = any(field in json_data for field in self.processing_fields)
                    
                    if has_target_fields:
                        # 包含目标字段，进行加密/解密处理
                        json_data, modified = self._process_json_data(json_data, url, is_response=True)
                        
                        if modified:
                            # 更新响应内容
                            flow.response.content = json.dumps(json_data, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
                            flow.response.headers["Content-Length"] = str(len(flow.response.content))
                    else:
                        # 如果不包含目标字段，记录日志但不处理
                        self.logger.log(None, self.logger._format_log_message(
                            url, 'response', content, content, is_response=True
                        ))
                        
                except json.JSONDecodeError as e:
                    # JSON解析失败，记录错误
                    self.logger.log(None, f"响应JSON解析失败: {str(e)}")

            # 处理表单格式的响应
            elif "application/x-www-form-urlencoded" in content_type:
                try:
                    # 检查表单中是否包含需要处理的字段
                    has_target_fields = any(f"{field}=" in content for field in self.processing_fields)
                    
                    if has_target_fields:
                        # 包含目标字段，进行加密/解密处理
                        new_content, modified = self._process_form_data(content, url, is_response=True)
                        
                        if modified:
                            # 更新响应内容
                            flow.response.content = new_content.encode('utf-8')
                            flow.response.headers["Content-Length"] = str(len(flow.response.content))
                    else:
                        # 如果不包含目标字段，记录日志但不处理
                        self.logger.log(None, self.logger._format_log_message(
                            url, 'response', content, content, is_response=True
                        ))
                        
                except UnicodeDecodeError as e:
                    # 解码失败，记录错误
                    self.logger.log(None, f"响应表单数据解码失败: {str(e)}")

            else:
                # 其他格式（text/html, text/plain等）
                # 尝试智能判断：先检查是否为Content-Type错误的JSON
                try:
                    json_data = json.loads(content)
                    # 是JSON但Content-Type错误，检查是否包含目标字段
                    has_target_fields = any(field in json_data for field in self.processing_fields)
                    
                    if has_target_fields:
                        # 按JSON处理
                        json_data, modified = self._process_json_data(json_data, url, is_response=True)
                        if modified:
                            flow.response.content = json.dumps(json_data, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
                            flow.response.headers["Content-Length"] = str(len(flow.response.content))
                            
                except json.JSONDecodeError:
                    # 不是JSON，检查是否可能是表单格式
                    has_target_fields = any(f"{field}=" in content for field in self.processing_fields)
                    
                    if has_target_fields:
                        # 尝试按表单处理
                        try:
                            new_content, modified = self._process_form_data(content, url, is_response=True)
                            if modified:
                                flow.response.content = new_content.encode('utf-8')
                                flow.response.headers["Content-Length"] = str(len(flow.response.content))
                        except Exception:
                            # 处理失败，保持原样（纯文本/HTML等不包含结构化字段）
                            pass
                    else:
                        # 对于纯文本/HTML等不包含目标字段的响应，记录日志但不处理
                        self.logger.log(None, self.logger._format_log_message(
                            url, 'response', content, content, is_response=True
                        ))

        except UnicodeDecodeError as e:
            # 无法解码为UTF-8（二进制数据），直接跳过
            pass
        except Exception as e:
            # 响应处理过程中的其他错误
            self.logger.log(None, f"响应处理失败: {str(e)}")

    def done(self) -> None:
        """
        脚本结束时调用
        
        可以在这里进行清理工作，如：
        - 关闭文件句柄
        - 清理临时数据
        - 记录统计信息
        
        目前暂无特殊处理需求
        """
        pass 