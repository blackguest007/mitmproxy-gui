"""
DES-CBC 加密/解密测试脚本

使用方法:
    python des_cbc_test.py

功能：
    1. 使用与前端相同的加密参数
    2. 支持用户输入字符串进行加密测试
    3. 显示加密前后的数据对比
"""

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64
import json


def encrypt_des_cbc(plain_text: str, key: str = "12345678", iv: str = "12345678") -> str:
    """
    DES-CBC 加密函数
    
    Args:
        plain_text: 待加密的文本
        key: 密钥（8字节）
        iv: 初始化向量（8字节）
    
    Returns:
        str: Base64编码的加密结果
    """
    try:
        # 创建 DES-CBC 加密器
        cipher = DES.new(key.encode('utf-8'), DES.MODE_CBC, iv.encode('utf-8'))

        # 对数据进行填充和加密
        padded_data = pad(plain_text.encode('utf-8'), DES.block_size)
        encrypted_data = cipher.encrypt(padded_data)

        # Base64 编码
        return base64.b64encode(encrypted_data).decode('utf-8')
    except Exception as e:
        print(f"加密错误: {e}")
        return None


def decrypt_des_cbc(encrypted_text: str, key: str = "12345678", iv: str = "12345678") -> str:
    """DES-CBC 解密函数"""
    try:
        encrypted_data = base64.b64decode(encrypted_text)
        cipher = DES.new(key.encode('utf-8'), DES.MODE_CBC, iv.encode('utf-8'))
        decrypted_data = cipher.decrypt(encrypted_data)
        unpadded_data = unpad(decrypted_data, DES.block_size)
        return unpadded_data.decode('utf-8')
    except Exception as e:
        print(f"解密错误: {e}")
        return None


def main():
    print("DES-CBC 加密/解密测试工具")
    print("=" * 50)
    print("使用与前端相同的加密参数:")
    print("密钥(key): 12345678")
    print("初始向量(iv): 12345678")
    print("=" * 50)

    while True:
        # 获取用户输入
        user_input = input("\n请输入要加密的内容 (输入 'q' 退出): ")
        if user_input.lower() == 'q':
            break

        # 构造与前端相同的数据结构
        data = {"username": user_input}
        json_data = json.dumps(data)

        # 加密
        encrypted = encrypt_des_cbc(json_data)

        if encrypted:
            print("\n加密结果:")
            print("-" * 50)
            print(f"原始数据: {json_data}")
            print(f"加密后: {encrypted}")

            # 解密验证
            decrypted = decrypt_des_cbc(encrypted)
            print(f"\n解密验证:")
            print(f"解密后: {decrypted}")
            print("-" * 50)

            # 构造完整的请求数据
            request_data = {"data": encrypted}
            print(f"\n完整的请求数据:")
            print(json.dumps(request_data, indent=2))

        # 测试前端传来的加密数据
        print("\n是否要测试解密前端数据? (y/n)")
        test_frontend = input().lower()
        if test_frontend == 'y':
            frontend_data = input("请输入前端加密的数据: ")
            decrypted_frontend = decrypt_des_cbc(frontend_data)
            if decrypted_frontend:
                print(f"\n前端数据解密结果:")
                print(f"解密后: {decrypted_frontend}")


if __name__ == "__main__":
    main()
