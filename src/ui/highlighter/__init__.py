"""
Syntax highlighter module.
Provides syntax highlighting functionality for Python code and logs.
"""

from .python_highlighter import PythonHighlighter
from .log_highlighter import LogHighlighter

__all__ = ['PythonHighlighter', 'LogHighlighter'] 