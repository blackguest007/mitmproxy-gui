# -*- coding: utf-8 -*-
"""
DES-CBC 加密数据发送测试工具

使用方法:
    python send_des_cbc.py

功能:
    1. 发送固定的测试数据包
    2. password字段通过mitmproxy加密
    3. 发送到burp代理(8080端口)
    4. 通过mitmproxy代理(9999端口)
"""

import requests
import json
import sys
import time
from datetime import datetime
from typing import Optional

# 设置控制台编码为 utf-8
if sys.platform.startswith('win'):
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8')

def send_request(url: str, data: dict, headers: dict = None) -> Optional[requests.Response]:
    """发送请求并返回响应"""
    try:
        # 设置代理链：mitmproxy(9999) -> burp(8080)
        proxies = {
            "http": "http://127.0.0.1:9999",
            "https": "http://127.0.0.1:9999"
        }
        
        # 创建session并设置代理
        session = requests.Session()
        session.proxies = proxies
        
        # 设置目标URL为burp地址
        burp_url = "http://127.0.0.1:8080/login_check.php"
        
        # 禁用 SSL 警告
        import urllib3
        urllib3.disable_warnings()
        
        print(f"\n发送请求到: {burp_url}")
        print(f"使用代理: {proxies}")
        print(f"请求数据: {json.dumps(data, ensure_ascii=False)}")
        
        # 发送到burp代理
        response = session.post(burp_url, data=data, headers=headers, verify=False)
        return response
    except Exception as e:
        print(f"请求错误: {e}")
        return None

def format_request_info(url: str, data: dict, headers: dict, response: requests.Response) -> str:
    """格式化请求和响应信息"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    info = [
        f"\n{'='*50}",
        f"时间: {timestamp}",
        f"\n请求信息:",
        f"URL: {url}",
        f"方法: POST",
        f"请求头: {json.dumps(headers, ensure_ascii=False, indent=2)}",
        f"请求数据: {json.dumps(data, ensure_ascii=False, indent=2)}",
        f"\n响应信息:",
        f"状态码: {response.status_code}",
        f"响应头: {json.dumps(dict(response.headers), ensure_ascii=False, indent=2)}",
        f"响应内容: {response.text}",
        f"{'='*50}\n"
    ]
    return '\n'.join(info)

def main():
    print("DES-CBC 加密数据发送测试工具")
    print("="*50)
    print("说明：")
    print("1. 数据将通过 mitmproxy(9999端口) 加密")
    print("2. 加密后的数据将发送到 burp(8080端口)")
    print("3. password字段将被加密")
    print("="*50)
    
    # 固定的测试数据
    test_data = {
        "m": "6",
        "username": "admin",
        "password": "admin"
    }
    
    # 设置请求头
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Host": "127.0.0.1:8080"  # 添加Host头
    }
    
    try:
        while True:
            print("\n按回车键发送测试数据包 (输入 'q' 退出)...")
            user_input = input().strip()
            
            if user_input.lower() == 'q':
                break
            
            # 发送请求
            print("\n正在发送请求...")
            response = send_request("http://127.0.0.1:8080/login_check.php", test_data, headers)
            
            if response:
                # 打印请求和响应信息
                log_info = format_request_info("http://127.0.0.1:8080/login_check.php", test_data, headers, response)
                print(log_info)
            
            # 等待一下，避免请求太快
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\n程序已退出")
    except Exception as e:
        print(f"\n发生错误: {e}")
    finally:
        print("\n感谢使用！")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n程序已退出")
    except Exception as e:
        print(f"\n程序出错: {e}")
    finally:
        print("\n感谢使用！")