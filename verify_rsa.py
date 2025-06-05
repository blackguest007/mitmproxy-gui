from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from Crypto.Cipher import PKCS1_v1_5  # 添加PKCS1_v1_5支持

# 公钥
public_key_pem = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0Llg1bVZhnyslfezwfeOkvnXW
q59bDtmQyHvxkP/38Fw8QQXBfROCgzGc+Te6pOPl6Ye+vQ1rAnisBaP3rMk40i3O
pallzVkuwRKydek3V9ufPpZEEH4eBgInMSDiMsggTWxcI/Lvag6eHjkSc67RTrj9
6oxj0ipVRqjxW4X6HQIDAQAB
-----END PUBLIC KEY-----"""

# 私钥
private_key_pem = """-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC0Llg1bVZhnyslfezwfeOkvnXWq59bDtmQyHvxkP/38Fw8QQXB
fROCgzGc+Te6pOPl6Ye+vQ1rAnisBaP3rMk40i3OpallzVkuwRKydek3V9ufPpZE
EH4eBgInMSDiMsggTWxcI/Lvag6eHjkSc67RTrj96oxj0ipVRqjxW4X6HQIDAQAB
AoGAEE2pOZxdFpQ6aTgNum0Jrhx1uSjqUGj1kr4xSNhf8OVU0zbm+G0C2OpaEOQU
ANVusZ0B5WZh0m700EvqXDzMMCsa9QhKPP4z9Nd09RHdcQtysbSXnWc2VKDYxiqy
bIsnnlHRemCqHzQVqLaoKa0OVGFouunSqKFiVbXZ9bb/aMECQQDhYD97TI5CpHxU
7tW67uphUD4xoND3v5ENE//9mgjjJsxnNarpYQDcZgPN2DNMSVmBzuItiiTBuLBE
uXDSBoGFAkEAzKn7H7Aa9G6hLfvHBfxVYtOuybqQwxsdXpQ6kH14dH2a+2A2tIw9
M2U4/pNz89nLC0pzWaYwCgNXHsmeBjYtuQJAYxT5U6+Ya1v8/Sny9LfMevPYI+Fb
fU/O6Tz9sfRiK9sGyekiNm/a/Qosafa+tq8YlqTpcrPk7PXRKKWOIAeUMQJAZDqO
eBtHaBNRrfJSqnTD4C0ouTQ7tsDtpibTc3Vu6yWkI50fzVWslyHoQow1yeMME9B3
Ix1HA3BVVweH8yTPSQJBAKY6NQgHEonErU0k7KzYQFncUAwp3k/TztZYVe86WNjk
3Ans1T2Dexf5w8pu0TStXxrBNI0MjP9OstFUSR8v92o=
-----END RSA PRIVATE KEY-----"""

# 加密值
encrypted_text1 = "q+12D72EEflYIUNI2LSusE4nYyMeLrnwPkWykPDagCbxgTsJY01qytzktnVYBD3nPNhc5+FrIP+6nwyQLQc4Q50/hMzTBC+rz3thtjY7HgEaO87hDkyaW5+s9UFy/PI/qmTZ1+LwdUhwZ7B5DYwCk/6kTk5Alfa5GfCkX/bxwA8="
encrypted_text2 = "j1q05kD4x+toPoq4iZZ10bt/k6TJ96JQ6Eg/qhF0f49IaU2EZl2BgaQtuD/5Od5H7d91Vcomx+iqx+TwvcS+uG3bYaHWgf3RAhxRuBj/wsDTOls4UEtXzyjOMZBrxV4St+dO2qxE/4dK1c6O1iwhEfLkliDV/8s5g0ofy1KjzBQ="

def encrypt_rsa(text):
    try:
        # 加载公钥
        public_key = RSA.import_key(public_key_pem)
        # 使用PKCS1_v1_5进行加密（与jsencrypt.js保持一致）
        cipher = PKCS1_v1_5.new(public_key)
        
        # 加密
        encrypted_data = cipher.encrypt(text.encode('utf-8'))
        
        # Base64编码
        return base64.b64encode(encrypted_data).decode('utf-8')
    except Exception as e:
        return f"加密失败: {str(e)}"

def decrypt_rsa(encrypted_text):
    try:
        # 加载私钥
        private_key = RSA.import_key(private_key_pem)
        # 使用PKCS1_v1_5进行解密（与jsencrypt.js保持一致）
        cipher = PKCS1_v1_5.new(private_key)
        
        # Base64解码
        encrypted_data = base64.b64decode(encrypted_text)
        
        # 解密
        decrypted_data = cipher.decrypt(encrypted_data, None)
        
        # UTF-8解码
        return decrypted_data.decode('utf-8')
    except Exception as e:
        return f"解密失败: {str(e)}"

# 验证两个加密值
print("第一个加密值解密结果:", decrypt_rsa(encrypted_text1))
print("第二个加密值解密结果:", decrypt_rsa(encrypted_text2))

# 使用相同公钥加密"admin"
print("\n使用相同公钥加密'admin':")
encrypted_admin = encrypt_rsa("admin")
print("加密结果:", encrypted_admin)
print("解密验证:", decrypt_rsa(encrypted_admin)) 