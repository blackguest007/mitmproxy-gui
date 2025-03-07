import os
import textwrap


def handle_rsa_keys(window, mode, key):
    """处理RSA密钥并将其保存为本地文件

    此函数根据用户输入的RSA密钥，将其保存为PEM格式的文件。
    根据模式（加密或解密），选择保存公钥或私钥。

    参数:
        window: 窗口对象，用于访问脚本加载器
        mode: 模式，'Encrypt' 或 'Decrypt'
        key: RSA密钥内容

    返回:
        tuple: 包含密钥路径和错误信息的元组
    """
    try:
        if not key:  # 添加空值检查
            return None, "密钥不能为空"

        # 获取正确的目录路径 - 注意这里改为 decryptTools
        script_dir = os.path.join(window.script_loader.root_path, "src", "scripts", "decryptTools")
        # 根据模式选择保存的文件名
        pem_file_path = os.path.join(script_dir, "rsa_public_key.pem" if mode == "Encrypt" else "rsa_private_key.pem")

        # 确保密钥内容是正确的PEM格式
        key_content = key.strip()
        if mode == "Encrypt":
            if "-----BEGIN PUBLIC KEY-----" not in key_content:
                key_content = ("-----BEGIN PUBLIC KEY-----\n" +
                               "\n".join(textwrap.wrap(key_content, 64)) +
                               "\n-----END PUBLIC KEY-----")
        elif mode == "Decrypt":
            if "-----BEGIN RSA PRIVATE KEY-----" not in key_content:
                key_content = ("-----BEGIN RSA PRIVATE KEY-----\n" +
                               "\n".join(textwrap.wrap(key_content, 64)) +
                               "\n-----END RSA PRIVATE KEY-----")

        # 保存PEM格式的密钥到文件
        with open(pem_file_path, "w") as f:
            f.write(key_content)

        # 使用正斜杠路径，确保兼容性
        pem_file_path = pem_file_path.replace('\\', '/')
        print(f"密钥已保存到: {pem_file_path}")  # 添加调试信息
        return pem_file_path, ""

    except Exception as e:
        error_msg = f"保存RSA密钥失败: {str(e)}"
        print(error_msg)  # 打印错误信息
        window.packet_detail.append(f"❌ {error_msg}")
        return None, error_msg
