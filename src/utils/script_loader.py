"""
Script loader module.
Provides functionality for loading and managing encryption/decryption scripts.
"""

import os
from typing import Optional, Dict, Any
from PyQt6.QtWidgets import QComboBox, QTextEdit, QMainWindow
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt
import textwrap

from src.ui.highlighter import PythonHighlighter


class ScriptLoader:
    """脚本加载器，用于管理加密、解密和Hook脚本"""

    def __init__(self, window: QMainWindow):
        """初始化脚本加载器

        Args:
            window: 主窗口实例
        """
        self.window = window
        self.encrypt_combo: QComboBox = window.encrypt_script_combo
        self.decrypt_combo: QComboBox = window.decrypt_script_combo
        self.both_combo: QComboBox = window.both_script_combo
        self.hook_script_combo: QComboBox = window.hook_script_combo
        self.encrypt_content: QTextEdit = window.encrypt_script_content
        self.decrypt_content: QTextEdit = window.decrypt_script_content
        self.both_content: QTextEdit = window.both_script_content
        self.hook_script_content: QTextEdit = window.hook_script_content
        self.encrypt_params_input = window.encrypt_params_input

        # 设置编辑器的字体
        font = QFont("Consolas")
        font.setPointSize(14)  # 修改为合适的字体大小
        self.encrypt_content.setFont(font)
        self.decrypt_content.setFont(font)
        self.both_content.setFont(font)
        self.hook_script_content.setFont(font)

        # 为编辑器添加Python语法高亮
        self.encrypt_highlighter = PythonHighlighter(self.encrypt_content.document())
        self.decrypt_highlighter = PythonHighlighter(self.decrypt_content.document())
        self.both_highlighter = PythonHighlighter(self.both_content.document())
        self.hook_highlighter = PythonHighlighter(self.hook_script_content.document())

        # 添加字体缩放功能
        for editor in [self.encrypt_content, self.decrypt_content, self.both_content, self.hook_script_content]:
            editor.setAcceptRichText(False)  # 禁用富文本以确保正确的字体缩放
            editor.wheelEvent = lambda event, ed=editor: self._handle_wheel_event(event, ed)

        # 获取项目根目录的绝对路径
        self.root_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        # 加载脚本
        self.load_scripts()
        self._connect_signals()

        # 连接文本编辑器的内容变化信号到保存函数
        self.encrypt_content.textChanged.connect(
            lambda: self._save_current_script(is_encrypt=True)
        )
        self.decrypt_content.textChanged.connect(
            lambda: self._save_current_script(is_decrypt=True)
        )
        self.both_content.textChanged.connect(
            lambda: self._save_current_script(is_both=True)
        )
        self.hook_script_content.textChanged.connect(
            lambda: self._save_current_script(is_both=True)
        )

        # 记录当前正在编辑的脚本路径
        self.current_encrypt_path = None
        self.current_decrypt_path = None
        self.current_both_path = None
        self.current_hook_path = None

        # 初始加载第一个脚本（如果有的话）
        if self.encrypt_combo.count() > 0:
            self.show_encrypt_content(self.encrypt_combo.itemText(0))
        if self.decrypt_combo.count() > 0:
            self.show_decrypt_content(self.decrypt_combo.itemText(0))
        if self.both_combo.count() > 0:
            self.show_both_content(self.both_combo.itemText(0))
        if self.hook_script_combo.count() > 0:
            self.show_hook_content(self.hook_script_combo.itemText(0))

    def load_scripts(self) -> None:
        """加载加密、解密和Hook脚本到下拉框"""
        # 加载加密脚本
        encrypt_path = os.path.join(self.root_path, "scripts", "encryptTools")
        if os.path.exists(encrypt_path):
            for script in os.listdir(encrypt_path):
                if script.endswith('.py') and script != '__init__.py':
                    self.encrypt_combo.addItem(script)
                    print(f"加载加密脚本: {script}")

        # 加载解密脚本
        decrypt_path = os.path.join(self.root_path, "scripts", "decryptTools")
        if os.path.exists(decrypt_path):
            for script in os.listdir(decrypt_path):
                if script.endswith('.py') and script != '__init__.py':
                    self.decrypt_combo.addItem(script)
                    print(f"加载解密脚本: {script}")

        # 加载双向脚本
        both_path = os.path.join(self.root_path, "scripts", "bothTools")
        if not os.path.exists(both_path):
            os.makedirs(both_path)  # 如果目录不存在则创建
        if os.path.exists(both_path):
            for script in os.listdir(both_path):
                if script.endswith('.py') and script != '__init__.py':
                    self.both_combo.addItem(script)
                    print(f"加载双向脚本: {script}")

        # 加载Hook脚本
        hook_path = os.path.join(self.root_path, "scripts", "hookTools")
        if os.path.exists(hook_path):
            for script in os.listdir(hook_path):
                if script.endswith('.py') and script != '__init__.py':
                    self.hook_script_combo.addItem(script)  # 确保使用正确的combo名称
                    print(f"加载Hook脚本: {script}")

    def _connect_signals(self) -> None:
        """连接信号槽"""
        self.encrypt_combo.currentTextChanged.connect(self.show_encrypt_content)
        self.decrypt_combo.currentTextChanged.connect(self.show_decrypt_content)
        self.both_combo.currentTextChanged.connect(self.show_both_content)
        self.hook_script_combo.currentTextChanged.connect(self.show_hook_content)

    def _save_current_script(self, is_encrypt: bool = False, is_decrypt: bool = False, is_both: bool = False) -> None:
        """保存当前脚本内容

        Args:
            is_encrypt: 是否是加密脚本
            is_decrypt: 是否是解密脚本
            is_both: 是否是双向脚本
        """
        if is_both and self.current_both_path:
            content = self.both_content.toPlainText()
            path = self.current_both_path
        elif is_encrypt and self.current_encrypt_path:
            content = self.encrypt_content.toPlainText()
            path = self.current_encrypt_path
        elif is_decrypt and self.current_decrypt_path:
            content = self.decrypt_content.toPlainText()
            path = self.current_decrypt_path
        elif is_both and self.current_hook_path:
            content = self.hook_script_content.toPlainText()
            path = self.current_hook_path
        else:
            return

        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
                print(f"保存脚本成功: {path}")
        except Exception as e:
            print(f"保存脚本时出错: {e}")

    def show_encrypt_content(self, script_name: str) -> None:
        """显示加密脚本内容

        Args:
            script_name: 脚本名称
        """
        if not script_name:
            return

        try:
            script_path = os.path.join(self.root_path, "scripts", "encryptTools", script_name)
            print(f"尝试加载加密脚本: {script_path}")

            if not os.path.exists(script_path):
                self.encrypt_content.setPlainText(f"脚本文件不存在: {script_path}")
                self.current_encrypt_path = None
                return

            self.current_encrypt_path = script_path
            with open(script_path, 'r', encoding='utf-8') as f:
                content = f.read()
                self.encrypt_content.setPlainText(content)
                print(f"成功加载加密脚本: {script_name}")

        except Exception as e:
            error_msg = f"读取脚本时出错: {str(e)}"
            print(error_msg)
            self.encrypt_content.setPlainText(error_msg)
            self.current_encrypt_path = None

    def show_decrypt_content(self, script_name: str) -> None:
        """显示解密脚本内容

        Args:
            script_name: 脚本名称
        """
        if not script_name:
            return

        try:
            script_path = os.path.join(self.root_path, "scripts", "decryptTools", script_name)
            print(f"尝试加载解密脚本: {script_path}")

            if not os.path.exists(script_path):
                self.decrypt_content.setPlainText(f"脚本文件不存在: {script_path}")
                self.current_decrypt_path = None
                return

            self.current_decrypt_path = script_path
            with open(script_path, 'r', encoding='utf-8') as f:
                content = f.read()
                self.decrypt_content.setPlainText(content)
                print(f"成功加载解密脚本: {script_name}")

        except Exception as e:
            error_msg = f"读取脚本时出错: {str(e)}"
            print(error_msg)
            self.decrypt_content.setPlainText(error_msg)
            self.current_decrypt_path = None

    def show_both_content(self, script_name: str) -> None:
        """显示双向脚本内容

        Args:
            script_name: 脚本名称
        """
        if not script_name:
            return

        try:
            script_path = os.path.join(self.root_path, "scripts", "bothTools", script_name)
            print(f"尝试加载双向脚本: {script_path}")

            if not os.path.exists(script_path):
                self.both_content.setPlainText(f"脚本文件不存在: {script_path}")
                self.current_both_path = None
                return

            self.current_both_path = script_path
            with open(script_path, 'r', encoding='utf-8') as f:
                content = f.read()
                self.both_content.setPlainText(content)
                print(f"成功加载双向脚本: {script_name}")

        except Exception as e:
            error_msg = f"读取脚本时出错: {str(e)}"
            print(error_msg)
            self.both_content.setPlainText(error_msg)
            self.current_both_path = None

    def show_hook_content(self, script_name: str) -> None:
        """显示Hook脚本内容

        Args:
            script_name: 脚本名称
        """
        if not script_name:
            return

        try:
            script_path = os.path.join(self.root_path, "scripts", "hookTools", script_name)
            print(f"尝试加载Hook脚本: {script_path}")

            if not os.path.exists(script_path):
                self.hook_script_content.setPlainText(f"脚本文件不存在: {script_path}")
                self.current_hook_path = None
                return

            self.current_hook_path = script_path
            with open(script_path, 'r', encoding='utf-8') as f:
                content = f.read()
                self.hook_script_content.setPlainText(content)
                print(f"成功加载Hook脚本: {script_name}")

        except Exception as e:
            error_msg = f"读取脚本时出错: {str(e)}"
            print(error_msg)
            self.hook_script_content.setPlainText(error_msg)
            self.current_hook_path = None

    def _handle_wheel_event(self, event, editor: QTextEdit) -> None:
        """处理鼠标滚轮事件，实现字体缩放

        Args:
            event: 鼠标事件
            editor: 文本编辑器
        """
        if event.modifiers() == Qt.KeyboardModifier.ControlModifier:
            # 获取当前字体
            font = editor.font()
            # 根据滚轮方向调整字体大小
            if event.angleDelta().y() > 0:
                font.setPointSize(font.pointSize() + 1)
            else:
                font.setPointSize(max(1, font.pointSize() - 1))
            # 应用新字体
            editor.setFont(font)
            event.accept()
        else:
            # 如果不是Ctrl+滚轮，则执行默认的滚动行为
            QTextEdit.wheelEvent(editor, event)

    def generate_command(self, mode: str, **kwargs: Any) -> Optional[str]:
        """根据模式生成对应的命令"""
        try:
            if mode == "Encrypt":
                encrypt_port = self.window.listen_port_input.text() or "8888"
                encrypt_script = self.encrypt_combo.currentText()
                if not encrypt_script:
                    return None

                script_dir = os.path.join(self.root_path, "scripts", "encryptTools", encrypt_script)
                if not os.path.exists(script_dir):
                    print(f"脚本文件不存在: {script_dir}")
                    return None

                # 获取用户输入的参数
                field = self.encrypt_params_input.text().strip() or "password"  # 默认值为 password
                field_param = f'field="{field}"'  # 添加 field= 前缀和引号

                # 构建命令参数
                params = []
                
                # 添加key参数，RSA不需要iv参数
                if 'rsa.py' in encrypt_script:
                    if 'key' in kwargs:
                        params.append(f"public_key={kwargs['key']}")
                else:
                    if 'key' in kwargs:
                        params.append(f"key={kwargs['key']}")
                    
                # 只有非RSA算法才添加iv参数
                if 'iv' in kwargs and kwargs['iv'] and 'rsa.py' not in encrypt_script:
                    params.append(f"iv={kwargs['iv']}")
                    
                # 构建完整命令
                command = f'mitmdump -p {encrypt_port} -s "{script_dir}" --ssl-insecure {field_param} {" ".join(params)}'
                print(f"生成的加密命令: {command}")
                return command

            elif mode == "Decrypt":
                decrypt_port = self.window.lineEdit.text() or "8888"
                decrypt_script = self.decrypt_combo.currentText()
                if not decrypt_script:
                    return None

                script_dir = os.path.join(self.root_path, "scripts", "decryptTools", decrypt_script)
                if not os.path.exists(script_dir):
                    print(f"脚本文件不存在: {script_dir}")
                    return None

                # 获取上游代理地址
                upstream = f"--mode upstream:http://127.0.0.1:{self.window.upstream_input.text()or'8080'}"

                # 获取用户输入的参数
                field = self.encrypt_params_input.text().strip() or "password"  # 默认值为 password
                field_param = f'field="{field}"'  # 添加 field= 前缀和引号

                # 添加key参数，RSA不需要iv参数
                params = []
                if 'rsa.py' in decrypt_script:
                    if 'key' in kwargs:
                        params.append(f'private_key={kwargs["key"]}')
                else:
                    if 'key' in kwargs:
                        params.append(f'key={kwargs["key"]}')
                    
                # 只有非RSA算法才添加iv参数
                if 'iv' in kwargs and kwargs['iv'] and 'rsa.py' not in decrypt_script:
                    params.append(f'iv={kwargs["iv"]}')

                params_str = " ".join(params)

                command = f'mitmdump -p {decrypt_port} -s "{script_dir}" {upstream} --ssl-insecure {field_param} {params_str}'
                print(f"生成的解密命令: {command}")
                return command

            elif mode == "Both":
                # 获取解密端口和加密端口
                decrypt_port = self.window.lineEdit.text() or "8888"
                encrypt_port = self.window.listen_port_input.text() or "9999"
                
                # 使用bothTools目录中的脚本
                script = self.both_combo.currentText()
                if not script:
                    return None

                # 构建脚本路径（使用完整路径）
                script_path = f"scripts/bothTools/{script}"
                full_script_path = os.path.join(self.root_path, script_path).replace("\\", "/")
                
                if not os.path.exists(full_script_path):
                    print(f"脚本文件不存在: {full_script_path}")
                    return None

                # 获取上游代理地址
                upstream_port = self.window.upstream_input.text() or "8080"
                upstream = f"--mode upstream:http://127.0.0.1:{upstream_port}"

                # 获取用户输入的参数
                field = self.encrypt_params_input.text().strip() or "password"  # 默认值为 password
                field_param = f'field="{field}"'  # 添加 field= 前缀和引号

                # 获取密钥和IV值
                encrypt_key = kwargs.get('key', {}).get('encrypt', '')
                decrypt_key = kwargs.get('key', {}).get('decrypt', '')
                encrypt_iv = kwargs.get('iv', {}).get('encrypt', '')
                decrypt_iv = kwargs.get('iv', {}).get('decrypt', '')

                # 检查是否是RSA脚本
                if 'rsa.py' in script.lower():
                    # 使用 bothTools 目录下的密钥文件
                    both_dir = os.path.join(self.root_path, "scripts", "bothTools").replace("\\", "/")
                    encrypt_command = f'mitmdump -p {encrypt_port} -s "{full_script_path}" --ssl-insecure {field_param} public_key={both_dir}/rsa_public_key.pem'
                    decrypt_command = f'mitmdump -p {decrypt_port} -s "{full_script_path}" {upstream} --ssl-insecure {field_param} private_key={both_dir}/rsa_private_key.pem'
                    print("+++++++++++++++++++++++++++++++++++")
                    # 打印命令和路径信息，但不显示私钥内容
                    print(f"生成的加密命令: {encrypt_command}")
                    print(f"加密密钥路径: {both_dir}/rsa_public_key.pem")
                    print(f"生成的解密命令: {decrypt_command}")
                    print(f"解密密钥路径: {both_dir}/rsa_private_key.pem")
                else:
                    # 非RSA脚本，添加普通的key和iv参数
                    encrypt_command = f'mitmdump -p {encrypt_port} -s "{full_script_path}" --ssl-insecure {field_param} key="{encrypt_key}" iv="{encrypt_iv}"'
                    decrypt_command = f'mitmdump -p {decrypt_port} -s "{full_script_path}" {upstream} --ssl-insecure {field_param} key="{decrypt_key}" iv="{decrypt_iv}"'
                    
                    # 打印命令信息
                    print(f"生成的加密命令: {encrypt_command}")
                    print(f"生成的解密命令: {decrypt_command}")

                # 返回两个命令
                return [decrypt_command, encrypt_command]

            return None
        except Exception as e:
            print(f"生成命令时出错: {e}")
            return None

    def cleanup(self) -> None:
        """清理资源"""
        try:
            # 保存所有打开的脚本
            self._save_current_script(is_encrypt=True)
            self._save_current_script(is_decrypt=True)
            self._save_current_script(is_both=True)
        except Exception as e:
            print(f"清理资源时出错: {e}")

    def stop_proxy(self) -> None:
        """停止代理"""
        try:
            # 清理资源
            self.cleanup()
        except Exception as e:
            print(f"停止代理时出错: {e}") 