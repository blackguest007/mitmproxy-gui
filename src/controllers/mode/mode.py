# path:/src/mode/mode.py

# 初始化加密模式,并调整按钮更新
def init_mode(window):
    """初始化模式相关的UI元素"""

    # 初始化显示状态
    update_mode(window)
    
    # 初始化Default模式的命令
    if hasattr(window, 'script_loader'):
        current_mode = window.mode_combo.currentText()
        if current_mode == "Default":
            command = window.script_loader.generate_command("default")
        elif current_mode == "Encrypt":
            command = window.script_loader.generate_command("encrypt")
        elif current_mode == "Decrypt":
            command = window.script_loader.generate_command("decrypt")
        elif current_mode == "Both":
            command = window.script_loader.generate_command("both")
            
        if command and hasattr(window, 'proxy_thread'):
            window.proxy_thread.command = command


def update_mode(window):
    """根据当前模式更新UI状态"""
    current_mode = window.mode_combo.currentText()

    # 基础控制按钮只在Default模式显示
    control_buttons = [window.intercept_btn, window.forward_btn, window.drop_btn]
    
    if current_mode == "Default":
        window.start_btn.hide()  # 在Default模式下隐藏Start Proxy按钮
        for btn in control_buttons:
            btn.show()  # 显示基础控制按钮
    else:
        window.start_btn.show()  # 在其他模式下显示Start Proxy按钮
        for btn in control_buttons:
            btn.hide()  # 隐藏基础控制按钮

    # 更新加密参数输入框显示状态
    encrypt_params_label = window.encrypt_params_label
    encrypt_params_input = window.encrypt_params_input
    
    # 获取所有key和iv相关控件
    dec_key_label = window.dec_key_label
    dec_key_input = window.dec_key_input
    dec_iv_label = window.dec_iv_label
    dec_iv_input = window.dec_iv_input
    enc_key_label = window.enc_key_label
    enc_key_input = window.enc_key_input
    enc_iv_label = window.enc_iv_label
    enc_iv_input = window.enc_iv_input

    # 获取端口相关控件
    dec_port_label = window.label  # dec_Listen Port label
    dec_port_input = window.lineEdit  # dec_Listen Port input
    enc_port_label = window.listen_port_label  # enc_Listen Port label
    enc_port_input = window.listen_port_input  # enc_Listen Port input

    if current_mode == "Default":
        # 只显示监听端口
        dec_port_label.show()
        dec_port_input.show()
        dec_port_label.setText('Listen Port:')  # 默认模式显示为 Listen Port
        
        # 隐藏其他所有控件
        encrypt_params_label.hide()
        encrypt_params_input.hide()
        dec_key_label.hide()
        dec_key_input.hide()
        dec_iv_label.hide()
        dec_iv_input.hide()
        enc_key_label.hide()
        enc_key_input.hide()
        enc_iv_label.hide()
        enc_iv_input.hide()
        window.upstream_label.hide()
        window.upstream_input.hide()
        enc_port_label.hide()
        enc_port_input.hide()
        
    elif current_mode == "Encrypt":
        # 显示加密相关控件
        encrypt_params_label.show()
        encrypt_params_input.show()
        enc_key_label.show()
        enc_key_input.show()
        enc_iv_label.show()
        enc_iv_input.show()
        enc_port_label.show()
        enc_port_input.show()
        enc_port_label.setText('Enc Listen Port:')  # 加密模式显示为 Enc Listen Port
        
        # 隐藏解密相关控件
        dec_key_label.hide()
        dec_key_input.hide()
        dec_iv_label.hide()
        dec_iv_input.hide()
        window.upstream_label.hide()
        window.upstream_input.hide()
        dec_port_label.hide()
        dec_port_input.hide()
        
    elif current_mode == "Decrypt":
        # 显示解密相关控件
        encrypt_params_label.show()
        encrypt_params_input.show()
        dec_key_label.show()
        dec_key_input.show()
        dec_iv_label.show()
        dec_iv_input.show()
        dec_port_label.show()
        dec_port_input.show()
        dec_port_label.setText('Dec Listen Port:')  # 解密模式显示为 Dec Listen Port
        window.upstream_label.show()
        window.upstream_input.show()
        
        # 隐藏加密相关控件
        enc_key_label.hide()
        enc_key_input.hide()
        enc_iv_label.hide()
        enc_iv_input.hide()
        enc_port_label.hide()
        enc_port_input.hide()
        
    elif current_mode == "Both":
        # 显示所有控件
        encrypt_params_label.show()
        encrypt_params_input.show()
        dec_key_label.show()
        dec_key_input.show()
        dec_iv_label.show()
        dec_iv_input.show()
        enc_key_label.show()
        enc_key_input.show()
        enc_iv_label.show()
        enc_iv_input.show()
        window.upstream_label.show()
        window.upstream_input.show()
        dec_port_label.show()
        dec_port_input.show()
        enc_port_label.show()
        enc_port_input.show()
        
        # Both模式下更新端口标签
        dec_port_label.setText('Dec Listen Port:')  # 解密端口显示为 Dec Listen Port
        enc_port_label.setText('Enc Listen Port:')  # 加密端口显示为 Enc Listen Port

def setup_mode_connections(window):
    """设置模式相关的信号连接"""
    window.mode_combo.currentTextChanged.connect(lambda: update_mode(window))
