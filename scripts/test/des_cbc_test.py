from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
import base64

def decrypt_des_cbc(encrypted_text: str, key: str, iv: str) -> str:
    # 确保密钥和IV都是8字节
    key_bytes = key.encode('utf-8')
    iv_bytes = iv.encode('utf-8')
    
    # 创建DES-CBC解密器
    cipher = DES.new(key_bytes, DES.MODE_CBC, iv_bytes)
    
    # Base64解码
    encrypted_data = base64.b64decode(encrypted_text)
    
    # 解密
    decrypted = cipher.decrypt(encrypted_data)
    
    # 去除填充
    result = unpad(decrypted, DES.block_size)
    
    # 转换为字符串
    return result.decode('utf-8')

# 测试数据
encrypted_text = "8ofNhYBfrq9VmTa3lgZHkkEhkqa3pcr8"
key = "12345678"
iv = "12345678"

try:
    decrypted = decrypt_des_cbc(encrypted_text, key, iv)
    print("解密结果:", decrypted)
except Exception as e:
    print("解密失败:", str(e))