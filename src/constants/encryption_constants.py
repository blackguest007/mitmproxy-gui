class EncryptionConstants:
    # 项目中实际存在的 AES 加密脚本
    AES_ALGORITHMS = ['aes_cbc.py', 'aes_ecb.py', 'aes_gcm.py']  # 支持 CBC/ECB/GCM 模式
    
    # 项目中实际存在的 DES 加密脚本
    DES_ALGORITHMS = ['des_cbc.py', 'des3_cbc.py', 'des_ecb.py', 'des3_ecb.py']  # 支持 DES/DES3 的 CBC/ECB 模式
    
    # 项目中实际存在的哈希算法脚本
    HASH_ALGORITHMS = ['md5.py', 'sha1.py', 'sha256.py', 'sha384.py', 'sha512.py']  # 支持 MD5/SHA1/SHA256/SHA384/SHA512
    
    # 项目中不需要密钥的算法脚本
    NO_KEY_ALGORITHMS = ['Base64.py', 'base64.py','md5.py', 'sha1.py', 'sha256.py', 'sha384.py', 'sha512.py']  # Base64编码和哈希算法不需要密钥
    
    AES_KEY_LENGTHS = [16, 24, 32]  # AES 密钥长度（128/192/256位）
    DES_KEY_LENGTH = [8, 16, 24]  # DES密钥长度(8字节)，3DES密钥长度(24字节)
    IV_LENGTH = 16  # AES-CBC/GCM 模式的 IV 长度（16字节） 