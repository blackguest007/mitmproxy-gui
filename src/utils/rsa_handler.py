"""
RSA key handler module.
Provides functionality for handling RSA keys in PEM format.
"""

import os
import textwrap
import base64
from typing import Tuple, Optional
from PyQt6.QtWidgets import QMainWindow


def format_pem_key(key_content: str, is_private: bool = False) -> str:
    """将密钥内容格式化为标准的 PEM 格式

    Args:
        key_content: 原始密钥内容
        is_private: 是否是私钥

    Returns:
        str: PEM 格式的密钥内容
    """
    # 检查是否已经是 PEM 格式
    if is_private:
        if "-----BEGIN RSA PRIVATE KEY-----" in key_content and "-----END RSA PRIVATE KEY-----" in key_content:
            return key_content
        # 添加 PEM 头部和尾部
        header = "-----BEGIN RSA PRIVATE KEY-----"
        footer = "-----END RSA PRIVATE KEY-----"
    else:
        if "-----BEGIN PUBLIC KEY-----" in key_content and "-----END PUBLIC KEY-----" in key_content:
            return key_content
        # 添加 PEM 头部和尾部
        header = "-----BEGIN PUBLIC KEY-----"
        footer = "-----END PUBLIC KEY-----"
    
    # 移除所有空白字符
    key_content = ''.join(key_content.split())
    
    # 确保密钥内容是有效的 Base64
    try:
        # 尝试解码 Base64，如果失败则说明不是有效的 Base64 字符串
        base64.b64decode(key_content)
    except Exception:
        raise ValueError("无效的密钥格式：密钥内容必须是有效的 Base64 编码")
    
    # 每 64 个字符添加换行符
    wrapped_key = '\n'.join(textwrap.wrap(key_content, 64))
    
    # 组合完整的 PEM 格式
    return f"{header}\n{wrapped_key}\n{footer}"


def handle_rsa_keys(window: QMainWindow, mode: str, key: str) -> Tuple[Optional[str], str]:
    """处理RSA密钥并将其保存为本地文件

    此函数根据用户输入的RSA密钥，将其保存为PEM格式的文件。
    根据模式（加密或解密），选择保存公钥或私钥。

    Args:
        window: 窗口对象，用于访问脚本加载器
        mode: 模式，'Encrypt' 或 'Decrypt' 或 'Both'
        key: RSA密钥内容

    Returns:
        Tuple[Optional[str], str]: 包含密钥路径和错误信息的元组
    """
    try:
        print(f"handle_rsa_keys 被调用: mode={mode}, key={key[:50]}...")  # 添加调试日志
        
        if not key:  # 添加空值检查
            print("密钥为空")  # 添加调试日志
            return None, "密钥不能为空"

        # 根据模式选择正确的目录和密钥类型
        if mode == "Both":
            # 在 Both 模式下，保存到 bothTools 目录
            script_dir = os.path.join(window.script_loader.root_path, "scripts", "bothTools")
            # 根据密钥内容判断是公钥还是私钥
            is_private = "PRIVATE KEY" in key
            print(f"Both模式: {'私钥' if is_private else '公钥'}")
        else:
            if mode == "Encrypt":
                script_dir = os.path.join(window.script_loader.root_path, "scripts", "encryptTools")
                is_private = False
            else:  # Decrypt mode
                script_dir = os.path.join(window.script_loader.root_path, "scripts", "decryptTools")
                is_private = True
            
        print(f"选择的目录: {script_dir}, is_private: {is_private}")  # 添加调试日志

        # 确保目录存在
        os.makedirs(script_dir, exist_ok=True)

        # 根据模式选择保存的文件名
        pem_file_path = os.path.join(script_dir, "rsa_public_key.pem" if not is_private else "rsa_private_key.pem")

        try:
            # 格式化密钥为 PEM 格式
            pem_content = format_pem_key(key, is_private)
            
            # 保存 PEM 格式的密钥到文件
            with open(pem_file_path, "w") as f:
                f.write(pem_content)

            # 使用正斜杠路径，确保兼容性
            pem_file_path = pem_file_path.replace('\\', '/')
            print(f"密钥已保存到: {pem_file_path}")  # 添加调试信息

            return pem_file_path, ""
            
        except ValueError as ve:
            error_msg = str(ve)
            print(error_msg)
            return None, error_msg
            
    except Exception as e:
        error_msg = f"处理RSA密钥时出错: {str(e)}"
        print(error_msg)
        return None, error_msg 