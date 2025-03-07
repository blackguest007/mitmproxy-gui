import re

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont


class LogHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.highlighting_rules = []

        # 成功信息格式（绿色）
        success_format = QTextCharFormat()
        success_format.setForeground(QColor("#98C379"))  # 绿色
        success_format.setFontWeight(QFont.Weight.Bold)
        self.highlighting_rules.append((
            r"✅.*$", success_format
        ))

        # 错误信息格式（红色）
        error_format = QTextCharFormat()
        error_format.setForeground(QColor("#E06C75"))  # 红色
        error_format.setFontWeight(QFont.Weight.Bold)
        self.highlighting_rules.append((
            r"❌.*$", error_format
        ))

        # 警告信息格式（黄色）
        warning_format = QTextCharFormat()
        warning_format.setForeground(QColor("#E5C07B"))  # 黄色
        warning_format.setFontWeight(QFont.Weight.Bold)
        self.highlighting_rules.append((
            r"⚠.*$", warning_format
        ))

        # 加载脚本信息格式（蓝色）
        loading_format = QTextCharFormat()
        loading_format.setForeground(QColor("#61AFEF"))  # 蓝色
        self.highlighting_rules.append((
            r"Loading script.*$", loading_format
        ))

        # 时间戳格式（灰色）
        timestamp_format = QTextCharFormat()
        timestamp_format.setForeground(QColor("#5C6370"))  # 灰色
        self.highlighting_rules.append((
            r"\[\d{2}:\d{2}:\d{2}\.\d{3}\]", timestamp_format
        ))

        # 命令执行格式（青色）
        command_format = QTextCharFormat()
        command_format.setForeground(QColor("#56B6C2"))  # 青色
        self.highlighting_rules.append((
            r"执行命令:.*$", command_format
        ))

        # 普通日志格式（白色）
        info_format = QTextCharFormat()
        info_format.setForeground(QColor("#ABB2BF"))  # 浅灰白色
        self.highlighting_rules.append((
            r"^(?!✅|❌|⚠|\[|Loading|执行命令).*$", info_format
        ))

    def highlightBlock(self, text):
        """高亮文本块"""
        for pattern, format in self.highlighting_rules:
            for match in re.finditer(pattern, text):
                self.setFormat(match.start(), match.end() - match.start(), format)