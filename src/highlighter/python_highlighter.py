from PyQt6.QtCore import Qt
from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
import re

class PythonHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.highlighting_rules = []

        # 关键字格式
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#FF6B6B"))
        keyword_format.setFontWeight(QFont.Weight.Bold)
        keywords = [
            # 基础关键字
            "and", "as", "assert", "break", "class", "continue", "def",
            "del", "elif", "else", "except", "False", "finally", "for",
            "from", "global", "if", "import", "in", "is", "lambda", "None",
            "nonlocal", "not", "or", "pass", "raise", "return", "True",
            "try", "while", "with", "yield",
            # 扩展关键字
            "self", "cls", "async", "await", "match", "case"
        ]
        for word in keywords:
            self.highlighting_rules.append((
                f"\\b{word}\\b", keyword_format
            ))

        # 内置函数格式
        builtin_format = QTextCharFormat()
        builtin_format.setForeground(QColor("#C678DD"))
        builtins = [
            "abs", "all", "any", "bin", "bool", "bytes", "callable", "chr",
            "classmethod", "compile", "complex", "delattr", "dict", "dir",
            "divmod", "enumerate", "eval", "exec", "filter", "float", "format",
            "frozenset", "getattr", "globals", "hasattr", "hash", "help", "hex",
            "id", "input", "int", "isinstance", "issubclass", "iter", "len",
            "list", "locals", "map", "max", "min", "next", "object", "oct",
            "open", "ord", "pow", "print", "property", "range", "repr",
            "reversed", "round", "set", "setattr", "slice", "sorted",
            "staticmethod", "str", "sum", "super", "tuple", "type", "vars",
            "zip", "__import__"
        ]
        for word in builtins:
            self.highlighting_rules.append((
                f"\\b{word}\\b", builtin_format
            ))

        # 装饰器格式
        decorator_format = QTextCharFormat()
        decorator_format.setForeground(QColor("#E5C07B"))
        self.highlighting_rules.append((
            r"@\w+", decorator_format
        ))

        # 字符串格式（包括三引号字符串）
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#98C379"))
        self.highlighting_rules.extend([
            (r'"[^"\\]*(\\.[^"\\]*)*"', string_format),
            (r"'[^'\\]*(\\.[^'\\]*)*'", string_format),
            (r'""".*?"""', string_format),
            (r"'''.*?'''", string_format)
        ])

        # 注释格式
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#5C6370"))
        comment_format.setFontItalic(True)
        self.highlighting_rules.append((
            r"#[^\n]*", comment_format
        ))

        # 函数定义格式
        function_format = QTextCharFormat()
        function_format.setForeground(QColor("#61AFEF"))
        self.highlighting_rules.append((
            r"\bdef\s+(\w+)", function_format
        ))

        # 类定义格式
        class_format = QTextCharFormat()
        class_format.setForeground(QColor("#E5C07B"))
        class_format.setFontWeight(QFont.Weight.Bold)
        self.highlighting_rules.append((
            r"\bclass\s+(\w+)", class_format
        ))

        # 数字格式
        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#D19A66"))
        self.highlighting_rules.extend([
            (r"\b[0-9]+\b", number_format),
            (r"\b0[xX][0-9a-fA-F]+\b", number_format),  # 十六进制
            (r"\b0[oO][0-7]+\b", number_format),        # 八进制
            (r"\b0[bB][01]+\b", number_format),         # 二进制
            (r"\b\d*\.\d+\b", number_format),           # 浮点数
        ])

        # 特殊方法格式（魔术方法）
        magic_format = QTextCharFormat()
        magic_format.setForeground(QColor("#56B6C2"))
        self.highlighting_rules.append((
            r"__\w+__", magic_format
        ))

    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            for match in re.finditer(pattern, text):
                self.setFormat(match.start(), match.end() - match.start(), format) 