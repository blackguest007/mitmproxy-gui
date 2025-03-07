"""
3DES-CBC 加密/解密测试脚本

使用方法:
    python des3_cbc_test.py

功能：
    1. 使用与前端相同的加密参数
    2. 支持用户输入字符串进行加密测试
    3. 显示加密前后的数据对比
"""

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import base64
import json

def encrypt_des3_cbc(plain_text: str, key: str = "24byteslongKeyfordes3!aa", iv: str = "8bytesIv") -> str:
    """3DES-CBC 加密函数"""
    try:
        # 确保密钥长度为24字节（192位）
        if len(key) < 24:
            key = key + (24 - len(key)) * '\0'
        elif len(key) > 24:
            key = key[:24]

        # 确保IV长度为8字节
        if len(iv) < 8:
            iv = iv + (8 - len(iv)) * '\0'
        elif len(iv) > 8:
            iv = iv[:8]

        cipher = DES3.new(key.encode('utf-8'), DES3.MODE_CBC, iv.encode('utf-8'))
        padded_data = pad(plain_text.encode('utf-8'), DES3.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return base64.b64encode(encrypted_data).decode('utf-8')
    except Exception as e:
        print(f"加密错误: {e}")
        return None

def decrypt_des3_cbc(encrypted_text: str, key: str = "24byteslongKeyfordes3!aa", iv: str = "8bytesIv") -> str:
    """3DES-CBC 解密函数"""
    try:
        # 确保密钥长度为24字节
        if len(key) < 24:
            key = key + (24 - len(key)) * '\0'
        elif len(key) > 24:
            key = key[:24]

        # 确保IV长度为8字节
        if len(iv) < 8:
            iv = iv + (8 - len(iv)) * '\0'
        elif len(iv) > 8:
            iv = iv[:8]

        encrypted_data = base64.b64decode(encrypted_text)
        cipher = DES3.new(key.encode('utf-8'), DES3.MODE_CBC, iv.encode('utf-8'))
        decrypted_data = cipher.decrypt(encrypted_data)
        unpadded_data = unpad(decrypted_data, DES3.block_size)
        return unpadded_data.decode('utf-8')
    except Exception as e:
        print(f"解密错误: {e}")
        return None

def main():
    print("3DES-CBC 加密/解密测试工具")
    print("=" * 50)
    print("使用与前端相同的加密参数:")
    print("密钥(key): 24byteslongKeyfordes3!aa")
    print("初始向量(iv): 8bytesIv")
    print("=" * 50)
    
    while True:
        # 获取用户输入
        user_input = input("\n请输入要加密的内容 (输入 'q' 退出): ")
        if user_input.lower() == 'q':
            break
            
        # 构造与前端相同的数据结构
        data = {"username": user_input}
        json_data = json.dumps(data, ensure_ascii=False)
        
        # 加密
        encrypted = encrypt_des3_cbc(json_data)
        
        if encrypted:
            print("\n加密结果:")
            print("-" * 50)
            print(f"原始数据: {json_data}")
            print(f"加密后: {encrypted}")
            
            # 解密验证
            decrypted = decrypt_des3_cbc(encrypted)
            print(f"\n解密验证:")
            print(f"解密后: {decrypted}")
            print("-" * 50)
            
            # 构造完整的请求数据
            request_data = {"data": encrypted}
            print(f"\n完整的请求数据:")
            print(json.dumps(request_data, indent=2, ensure_ascii=False))

        # 测试前端传来的加密数据
        print("\n是否要测试解密前端数据? (y/n)")
        test_frontend = input().lower()
        if test_frontend == 'y':
            frontend_data = input("请输入前端加密的数据: ")
            decrypted_frontend = decrypt_des3_cbc(frontend_data)
            if decrypted_frontend:
                print(f"\n前端数据解密结果:")
                print(f"解密后: {decrypted_frontend}")

if __name__ == "__main__":
    main() 