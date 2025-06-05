"""
Key validation module.
Provides functionality for validating encryption keys.
"""

from typing import Any
from PyQt6.QtWidgets import QMainWindow

from constants.encryption_constants import EncryptionConstants
from constants.error_messages import ErrorMessages


def validate_key_length(window: QMainWindow, script: str, key: str) -> bool:
    """验证密钥长度是否符合要求

    Args:
        window: 主窗口实例
        script: 选择的加密/解密脚本
        key: 输入的密钥

    Returns:
        bool: 验证是否通过
    """
    # 检查是否需要密钥
    if not key and script not in EncryptionConstants.NO_KEY_ALGORITHMS:
        window.packet_detail.append(ErrorMessages.KEY_REQUIRED)
        return False

    # 根据选择的脚本进行密钥长度检查
    if script in EncryptionConstants.AES_ALGORITHMS:
        if len(key) not in EncryptionConstants.AES_KEY_LENGTHS:
            window.packet_detail.append(ErrorMessages.AES_KEY_LENGTH_ERROR)
            return False
    elif script in EncryptionConstants.DES_ALGORITHMS:
        if len(key) not in EncryptionConstants.DES_KEY_LENGTH:
            window.packet_detail.append(ErrorMessages.DES_KEY_LENGTH_ERROR)
            return False

    return True 