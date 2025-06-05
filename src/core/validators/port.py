"""
Port validation module.
Provides functionality for validating port configurations.
"""

import os
import re
import sys
from typing import Dict, Union


class PortValidator:
    """端口配置验证器，支持全场景校验"""

    @staticmethod
    def validate(port_str: str) -> Dict[str, Union[bool, str, int]]:
        """
        综合验证端口配置

        :return: 包含校验结果的字典 {
            "valid": bool,       # 是否合法
            "value": int,        # 转换后的端口号（仅当valid=True时存在）
            "warning": str,      # 警告信息（如需要root权限）
            "error": str         # 错误描述（仅当valid=False时存在）
        }
        """
        # 基础清洗
        cleaned = port_str.strip()
        if not cleaned:
            return {"valid": False, "error": "端口不能为空"}

        # 格式校验
        if not re.match(r'^\d+$', cleaned):
            return {"valid": False, "error": "必须为纯数字"}

        # 数值转换
        try:
            port = int(cleaned)
        except ValueError:
            return {"valid": False, "error": "无效数字格式"}

        # 范围校验
        if not (0 <= port <= 65535):
            return {"valid": False, "error": "端口范围0-65535"}

        # 特殊端口警告
        result = {"valid": True, "value": port}
        if 1 <= port <= 1023 and not PortValidator._has_root():
            result["warning"] = "需管理员权限（Linux/Mac需sudo）"

        return result

    @staticmethod
    def _has_root() -> bool:
        """检查是否具有管理员权限"""
        try:
            return (sys.platform == 'win32') or (os.geteuid() == 0)
        except AttributeError:
            # Windows无euid概念
            return False 