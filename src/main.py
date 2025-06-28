# path: /src/main.py

# 主程序

import warnings
import os
import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QMessageBox
from PyQt6.uic import loadUi
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtWidgets import QTextEdit
from PyQt6.QtCore import Qt

# 过滤掉 Qt 的 transition 属性警告
warnings.filterwarnings("ignore", "Unknown property transition")
# 过滤掉 sip 的废弃警告
warnings.filterwarnings("ignore", "sipPyTypeDict() is deprecated")

from controllers.button_controller.button import setup_buttons
from ui.highlighter.python_highlighter import PythonHighlighter
from controllers.mode.mode import setup_mode_connections, update_mode
from utils.script_loader import ScriptLoader
from themes.theme import get_themes, init_themes
from ui.highlighter.log_highlighter import LogHighlighter


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # 设置窗口标题
<<<<<<< HEAD
        self.setWindowTitle("mitmproxy-gui V1.0.4 Created by @LingDu")
=======
        self.setWindowTitle("mitmproxy-gui V1.0.3 Created by @LingDu")
>>>>>>> 003e959c53f0a3ebe65ba51c3c236e85da3c6263

        # 初始化属性
        self.mitm_threads = []  # 用于存储当前运行的线程

        # 首先加载UI
        self.load_ui()  # 移到最前面

        # 设置窗口图标
        icon_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "resource", "logo", "img.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        else:
            print(f"Warning: Icon file not found at {icon_path}")

        # 其他初始化
        self.initialize_script_loader()
        self.initialize_highlighters()
        self.setup_buttons()
        self.setup_themes()

        # 调用初始化函数
        self.initialize()

    def initialize_ui(self):
        """加载用户界面"""
        try:
            self.load_ui()
        except Exception as e:
            print(f"Error loading UI: {e}")

    def initialize_script_loader(self):
        """初始化脚本加载器"""
        try:
            self.script_loader = ScriptLoader(self)
        except Exception as e:
            print(f"Error initializing script loader: {e}")

    def initialize_highlighters(self):
        """初始化代码和日志高亮器"""
        try:
            self.init_code_highlighter()
            self.log_highlighter = LogHighlighter(self.packet_detail.document())
        except Exception as e:
            print(f"Error initializing highlighters: {e}")

    def setup_buttons(self):
        """设置按钮的信号连接"""
        setup_buttons(self)

    def setup_themes(self):
        """设置主题"""
        get_themes(self)
        init_themes(self)

    def setup_mode_connections(self):
        """设置模式连接"""
        setup_mode_connections(self)

    def load_ui(self):
        """ 加载 .ui 文件 """
        # 获取当前文件所在目录
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # 构建 UI 文件的绝对路径
        ui_path = os.path.join(current_dir, "ui", "mitmproxy_gui.ui")
        
        if not os.path.exists(ui_path):
            raise FileNotFoundError(f"UI file not found: {ui_path}")
        
        loadUi(ui_path, self)

    def init_code_highlighter(self):
        """初始化代码高亮器"""
        # 设置代码编辑器字体
        font = QFont("Consolas")
        font.setPointSize(14)  # 改为14pt

        # 修改为正确的控件名称
        self.encrypt_script_content.setFont(font)
        self.decrypt_script_content.setFont(font)
        self.both_script_content.setFont(font)

        # 启用Ctrl+滚轮缩放
        for editor in [self.encrypt_script_content, self.decrypt_script_content, self.both_script_content]:
            editor.setAcceptRichText(False)  # 禁用富文本以确保正确的字体缩放
            editor.wheelEvent = lambda event, ed=editor: self._handle_wheel_event(event, ed)

        # 初始化高亮器
        self.highlighter_encrypt = PythonHighlighter(self.encrypt_script_content.document())
        self.highlighter_decrypt = PythonHighlighter(self.decrypt_script_content.document())
        self.highlighter_both = PythonHighlighter(self.both_script_content.document())

    def _handle_wheel_event(self, event, editor):
        """处理滚轮事件，实现Ctrl+滚轮缩放字体"""
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            delta = event.angleDelta().y()
            if delta > 0:
                editor.zoomIn()
            else:
                editor.zoomOut()
        else:
            # 调用原始的滚轮事件处理
            QTextEdit.wheelEvent(editor, event)

    def initialize(self):
        """初始化窗口设置"""
        # 设置默认模式
        self.mode_combo.setCurrentText("Default")

        # 更新UI状态
        update_mode(self)  # 确保在显示窗口之前更新UI状态


# 主程序入口
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
