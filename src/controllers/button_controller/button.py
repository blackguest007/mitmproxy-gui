# /button/button.py
import logging
import os
import subprocess
import traceback
import textwrap

from PyQt6.QtWidgets import QMessageBox, QTableWidgetItem
from PyQt6 import QtCore
from PyQt6.QtGui import QIcon, QDesktopServices
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QProcess, QUrl

from src.controllers.mode.mode import update_mode
from src.controllers.thread.mitmproxy_thread import MitmProxyThread
from src.core.validators import validate_key_length, PortValidator
from src.utils import handle_rsa_keys
from src.utils.script_loader import ScriptLoader
from src.constants.error_messages import ErrorMessages
from src.constants.mode_constants import ModeConstants
from src.constants.encryption_constants import EncryptionConstants
from src.constants.ui_constants import UIConstants
from src.constants.message_constants import MessageConstants

# 配置日志记录
logging.basicConfig(level=logging.INFO)


def forward_request(window):
    pass


def drop_request(window):
    pass


def setup_buttons(window):
    """ 设置按钮的点击事件 """
    window.start_btn.clicked.connect(lambda: start_proxy(window))
    window.intercept_btn.clicked.connect(lambda: toggle_intercept(window))
    window.forward_btn.clicked.connect(lambda: forward_request(window))
    window.drop_btn.clicked.connect(lambda: drop_request(window))

    # 添加表格行点击事件
    window.packet_table.itemClicked.connect(lambda item: show_packet_detail(window, item.row()))

    # 创建并添加"关于"菜单项
    about_action = window.menu.addAction(UIConstants.TOOLTIP_MENU)
    about_action.triggered.connect(lambda: QDesktopServices.openUrl(QUrl(UIConstants.GITHUB_URL)))

    # 设置关于按钮的提示文本
    window.menu.setToolTip(UIConstants.TOOLTIP_GITHUB)

    # 绑定模式选择变化的信号
    window.mode_combo.currentTextChanged.connect(lambda: update_mode(window))  # 绑定模式更新UI

    # 连接清空日志按钮
    window.clear_log_button.clicked.connect(lambda: clear_log(window))


def toggle_intercept(window):
    """改进后的拦截按钮逻辑"""
    try:
        # 停止拦截逻辑
        if window.intercept_btn.text() == UIConstants.BTN_INTERCEPT_ON:
            # 执行深度端口校验
            listen_port = window.lineEdit.text() if window.lineEdit.text() else "8888"
            validation = PortValidator.validate(listen_port)

            if not validation["valid"]:
                window.packet_detail.append(ErrorMessages.PORT_ERROR.format(validation['error']))
                return

            if "warning" in validation:
                window.packet_detail.append(f"⚠️ 注意: {validation['warning']}")

            window.intercept_btn.setText(UIConstants.BTN_INTERCEPT_OFF)
            # 改变拦截按钮的icon
            script_dir = os.path.dirname(os.path.abspath(__file__))
            icon_path = os.path.join(script_dir, "..", "..", "resource")
            window.intercept_btn.setIcon(QIcon(icon_path))
            window.intercept_btn.setIconSize(QtCore.QSize(16, 16))
            window.intercept_btn.setStyleSheet("background-color: #424647;")

            window.packet_detail.clear()  # 清空详情区域
            window.packet_detail.append(MessageConstants.INTERCEPT_STOPPED)

            # 停止当前的 mitmproxy 线程
            if hasattr(window, 'mitm_threads') and window.mitm_threads:
                for thread in window.mitm_threads:
                    thread.stop()
                    thread.wait()
                window.mitm_threads = []

        # 启动拦截逻辑
        else:
            # 执行深度端口校验
            listen_port = window.lineEdit.text() if window.lineEdit.text() else "8888"
            validation = PortValidator.validate(listen_port)

            if not validation["valid"]:
                window.packet_detail.append(ErrorMessages.PORT_ERROR.format(validation['error']))
                return

            if "warning" in validation:
                window.packet_detail.append(f"⚠️ 注意: {validation['warning']}")

            window.intercept_btn.setText(UIConstants.BTN_INTERCEPT_ON)
            # 改变拦截按钮的icon
            script_dir = os.path.dirname(os.path.abspath(__file__))
            icon_path = os.path.join(script_dir, "..", "..", "resource", "icon", "开关-开.png")
            window.intercept_btn.setIcon(QIcon(icon_path))
            window.intercept_btn.setIconSize(QtCore.QSize(16, 16))
            window.intercept_btn.setStyleSheet("background-color: #26649d;")

            # 创建新线程并启动
            window.mitm_thread = MitmProxyThread(listen_port)

            # 连接信号，将抓取的数据包添加到表格
            window.mitm_thread.new_packet.connect(lambda data: add_packet_to_table(window, data))

            window.packet_detail.clear()  # 清空详情区域
            window.packet_detail.append(MessageConstants.INTERCEPT_STARTED)

            # 启动 mitmproxy 线程
            window.mitm_thread.start()

    except Exception as e:
        print(f"拦截逻辑出错: {e}")
        window.packet_detail.append(f"❌ 拦截失败: {str(e)}")


def add_packet_to_table(window, row_data):
    """添加数据包到表格并自动显示第一个数据包的详细信息"""
    try:
        row_position = window.packet_table.rowCount()
        window.packet_table.insertRow(row_position)

        if len(row_data) < 8:
            print("Warning: row_data does not contain enough data.")
            return

        # 将数据包的完整信息存储到每个表格项的UserRole
        for column, value in enumerate(row_data[:7]):
            item = QTableWidgetItem(str(value))
            window.packet_table.setItem(row_position, column, item)

        # 将原始数据存储在第8列（隐藏列）
        raw_data_item = QTableWidgetItem(str(row_data[7]))
        window.packet_table.setItem(row_position, 7, raw_data_item)

        # 将数据包的完整信息存储为该行的自定义数据
        item = window.packet_table.item(row_position, 0)  # 获取第一列的item
        item.setData(Qt.ItemDataRole.UserRole, row_data)  # 保存完整数据包到UserRole
        print(f"成功添加数据包到表格: {row_data}")  # 调试打印

        # 自动显示第一个数据包的详情
        if row_position == 0:  # 这是第一个数据包
            show_packet_detail(window, 0)  # 自动显示第一个数据包的详情

    except Exception as e:
        print(f"Error adding packet to table: {e}")


def show_packet_detail(window, row):
    """显示选中行的数据包详情"""
    try:
        print(f"尝试显示第 {row} 行的数据包详情")  # 调试打印

        item = window.packet_table.item(row, 0)
        if item is None:
            print("错误: 未找到表格项")  # 调试打印
            return

        # 从自定义数据（UserRole）中获取数据包信息
        row_data = item.data(Qt.ItemDataRole.UserRole)
        if not row_data:
            print("错误: 未找到数据包信息")  # 调试打印
            return

        print(f"获取到的数据包信息: {row_data}")  # 调试打印

        # 清空并显示详细信息
        window.packet_detail.clear()

        # 手动解析请求头
        headers_str = row_data[6]  # 假设第7项包含完整的请求头字符串
        headers = {}
        lines = headers_str.split("\n")
        for line in lines:
            if not line.strip():  # 跳过空行
                continue
            # 使用冒号分割 key 和 value
            parts = line.split(":", 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()
                headers[key] = value

        # 拼接详情文本
        detail_text = f"""时间: {row_data[0]}
方法: {row_data[3]}
URL: {row_data[4]}

请求头:
{'-' * 50}
"""
        for key, value in headers.items():
            detail_text += f"{key}: {value}\n"

        raw_data = row_data[7]  # 原始数据字段
        detail_text += f"\n原始请求数据:\n{'-' * 50}\n{raw_data}"

        # 显示详细信息
        window.packet_detail.setPlainText(detail_text)
        print("成功显示数据包详情")  # 确保这行输出被打印

    except Exception as e:
        print(f"显示数据包详情时出错: {e}")
        import traceback
        traceback.print_exc()
        window.packet_detail.append(f"❌ 显示数据包详情时出错: {str(e)}")


import shlex


class CommandThread(QThread):
    output_signal = pyqtSignal(str)

    def __init__(self, command_list):
        super().__init__()
        self.command_list = command_list

    def run(self):
        try:
            print(f"Starting process with command: {self.command_list}")  # 调试输出
            process = subprocess.Popen(self.command_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                       encoding="utf-8")

            stdout, stderr = process.communicate()
            output = []
            if stdout:
                output.append(f"stdout:\n{stdout}")
            if stderr:
                output.append(f"stderr:\n{stderr}")
            full_output = "\n".join(output)

            if process.returncode == 0:
                self.output_signal.emit(f"✅ 命令执行成功\n{full_output}")
            else:
                self.output_signal.emit(f"❌ 命令执行失败 (code: {process.returncode})\n{full_output}")

        except Exception as e:
            self.output_signal.emit(f"❌ 执行时发生错误: {str(e)}")


def get_button_style(state):
    """获取按钮样式"""
    if state == "stop":
        return "background-color: red; color: white;"  # 停止时的样式
    else:
        return "background-color: #26649d; color: white;"  # 默认样式


def start_proxy(window, key=None, iv=None):
    """启动代理"""
    try:
        # 如果已经在运行，则停止
        if window.mitm_threads:
            for thread in window.mitm_threads:
                thread.stop()  # 停止每个线程
                thread.wait()  # 等待线程结束
            window.mitm_threads = []  # 清空线程列表
            window.start_btn.setText(UIConstants.BTN_START_PROXY)
            window.start_btn.setStyleSheet(get_button_style("default"))
            window.packet_detail.append(MessageConstants.PROXY_STOPPED)
            return

        # 启动代理的逻辑
        mode = window.mode_combo.currentText()
        decrypt_script = window.decrypt_script_combo.currentText()
        encrypt_script = window.encrypt_script_combo.currentText()
        des_key = window.dec_key_input.text().strip()
        des_iv = window.dec_iv_input.text().strip()
        enc_key = window.enc_key_input.text().strip()
        enc_iv = window.enc_iv_input.text().strip()

        if mode == ModeConstants.DEFAULT:
            window.mitm_thread = MitmProxyThread(listen_port=8888)
            window.mitm_thread.new_packet.connect(lambda data: add_packet_to_table(window, data))
            window.mitm_thread.start()
            window.packet_detail.append(MessageConstants.PROXY_STARTED.format("Default"))
        else:
            # 根据模式获取密钥和 IV
            if mode == ModeConstants.ENCRYPT:
                print(f"Encrypt Key: {enc_key}, IV: {enc_iv}")

                # 检查是否需要密钥
                if not validate_key_length(window, encrypt_script, enc_key):
                    return

                # 然后检查是否需要处理 RSA 密钥
                if 'rsa.py' in encrypt_script:
                    pem_path, error = handle_rsa_keys(window, mode, enc_key)
                    if error:
                        window.packet_detail.append(ErrorMessages.INVALID_MODE)
                        return
                    enc_key = pem_path  # 使用处理后的密钥路径

                # 检查密钥长度之前，确保用户选择了脚本
                if not enc_key and encrypt_script not in EncryptionConstants.NO_KEY_ALGORITHMS:
                    window.packet_detail.append(ErrorMessages.KEY_REQUIRED)  # 提示需要密钥
                    return

                # 生成命令
                commands = window.script_loader.generate_command(mode, key=enc_key, iv=enc_iv)

            elif mode == ModeConstants.DECRYPT:
                print(f"Decrypt Key: {des_key}, IV: {des_iv}")

                # 先验证密钥
                if not validate_key_length(window, decrypt_script, des_key):
                    return

                # 然后检查是否需要处理 RSA 密钥
                if 'rsa.py' in decrypt_script:
                    pem_path, error = handle_rsa_keys(window, mode, des_key)
                    if error:
                        window.packet_detail.append(ErrorMessages.INVALID_MODE)
                        return
                    des_key = pem_path  # 使用处理后的密钥路径
                    window.packet_detail.append(MessageConstants.DECRYPT_KEY_SAVED.format(des_key))

                # 检查密钥长度之前，确保用户选择了脚本
                if not des_key and decrypt_script not in EncryptionConstants.NO_KEY_ALGORITHMS:
                    window.packet_detail.append(ErrorMessages.KEY_REQUIRED)  # 提示需要密钥
                    return

                # 生成命令
                commands = window.script_loader.generate_command(mode, key=des_key, iv=des_iv)

            elif mode == ModeConstants.BOTH:
                key = {
                    'decrypt': window.dec_key_input.text().strip(),
                    'encrypt': window.enc_key_input.text().strip()
                }
                iv = {
                    'decrypt': window.dec_iv_input.text().strip(),
                    'encrypt': window.enc_iv_input.text().strip()
                }

                # 检查是否需要密钥
                if 'rsa.py' in encrypt_script and not key['encrypt']:
                    window.packet_detail.append(ErrorMessages.KEY_REQUIRED)
                    return
                if 'rsa.py' in decrypt_script and not key['decrypt']:
                    window.packet_detail.append(ErrorMessages.KEY_REQUIRED)
                    return

                # 获取当前选择的脚本
                both_script = window.both_script_combo.currentText()

                # 如果是 RSA 模式，处理密钥
                if 'rsa.py' in both_script.lower():
                    # 处理加密密钥（公钥）
                    if key['encrypt']:
                        pem_path, error = handle_rsa_keys(window, "Both", key['encrypt'])
                        if error:
                            window.packet_detail.append(ErrorMessages.INVALID_MODE)
                            return
                        key['encrypt'] = pem_path
                        print(f"加密密钥（公钥）已保存到: {pem_path}")

                    # 处理解密密钥（私钥）
                    if key['decrypt']:
                        # 确保私钥内容包含正确的 PEM 头部
                        if not "-----BEGIN RSA PRIVATE KEY-----" in key['decrypt']:
                            key['decrypt'] = f"-----BEGIN RSA PRIVATE KEY-----\n{key['decrypt']}\n-----END RSA PRIVATE KEY-----"
                        pem_path, error = handle_rsa_keys(window, "Both", key['decrypt'])
                        if error:
                            window.packet_detail.append(ErrorMessages.INVALID_MODE)
                            return
                        key['decrypt'] = pem_path
                        print(f"解密密钥（私钥）已保存到: {pem_path}")
                else:
                    # 非RSA脚本，直接使用密钥内容
                    print(f"非RSA脚本，使用原始密钥内容")
                    print(f"加密密钥: {key['encrypt'][:50]}...")
                    print(f"解密密钥: {key['decrypt'][:50]}...")

                # 生成命令
                commands = window.script_loader.generate_command(mode, key=key, iv=iv)
            if not commands:
                print(f"生成的命令: {commands}")    
                window.packet_detail.append(ErrorMessages.INVALID_MODE)
                return

            # 启动新线程
            if isinstance(commands, list):  # Both模式
                for cmd in commands:
                    print(f"生成的命令: {cmd}")
                    window.packet_detail.append(f"执行命令: {cmd}")
                    command_list = shlex.split(cmd)
                    thread = MitmProxyThread(command=command_list)  # 创建线程实例
                    thread.new_packet.connect(lambda data: add_packet_to_table(window, data))
                    thread.new_log.connect(lambda msg: window.packet_detail.append(msg))
                    thread.start()  # 启动线程
                    window.mitm_threads.append(thread)  # 添加到线程列表
            else:  # 单个命令模式,encrypt和decrypt模式
                print(f"生成的命令: {commands}")
                window.packet_detail.append(f"执行命令: {commands}")
                command_list = shlex.split(commands)
                window.mitm_thread = MitmProxyThread(command=command_list)
                window.mitm_thread.new_packet.connect(lambda data: add_packet_to_table(window, data))
                window.mitm_thread.new_log.connect(lambda msg: window.packet_detail.append(msg))
                window.mitm_thread.start()
                window.mitm_threads.append(window.mitm_thread)  # 添加到线程列表

            window.packet_detail.append(MessageConstants.PROXY_STARTED.format(mode))

        # 更新按钮状态
        window.start_btn.setText(UIConstants.BTN_STOP_PROXY)
        window.start_btn.setStyleSheet(get_button_style("stop"))

    except Exception as e:
        print(f"启动代理时出错: {e}")
        window.packet_detail.append(ErrorMessages.PROXY_START_ERROR.format(str(e)))
        # 确保在出错时重置按钮状态
        window.start_btn.setText(UIConstants.BTN_START_PROXY)
        window.start_btn.setStyleSheet(get_button_style("default"))  # 恢复默认样式


def clear_log(self):
    """清空日志内容"""
    self.packet_detail.clear()
    self.packet_detail.append(MessageConstants.LOG_CLEARED)