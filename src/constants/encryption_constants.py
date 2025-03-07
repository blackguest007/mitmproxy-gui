class EncryptionConstants:
    AES_ALGORITHMS = ['aes_cbc.py', 'aes_ecb.py', 'aes_cfb.py', 'aes_ofb.py', 'aes_ctr.py', 'aes_gcm.py', 'aes_ccm.py', 'aes_xts.py', 'aes_xts_128.py', 'aes_xts_256.py']  # 添加所有 AES 脚本
    DES_ALGORITHMS = ['des_cbc.py', 'des3_cbc','des_ecb.py', 'des_cfb.py', 'des_ofb.py', 'des_ctr.py', 'des_gcm.py', 'des_ccm.py', 'des_xts.py', 'des_xts_128.py', 'des_xts_256.py']  # 添加所有 DES 脚本
    HASH_ALGORITHMS = ['md5.py', 'sha1.py', 'sha256.py', 'sha512.py', 'hmac.py', 'hmac_md5.py', 'hmac_sha1.py', 'hmac_sha256.py', 'hmac_sha512.py']  # 添加所有哈希算法
    NO_KEY_ALGORITHMS = ['base64.py', 'md5.py','sha1.py','sha256.py','sha512.py','hmac.py','hmac_md5.py','hmac_sha1.py','hmac_sha256.py','hmac_sha512.py']  # 不需要密钥的算法
    AES_KEY_LENGTHS = [16, 24, 32]  # AES 密钥长度
    DES_KEY_LENGTH = [8,16,24] # DES 密钥长度,3DES 秘钥长度
    IV_LENGTH = 16  # IV 长度

    # 不需要密钥的加密算法列表
    NO_KEY_ALGORITHMS = ['base64.py', 'md5.py','sha1.py','sha256.py','sha512.py','hmac.py','hmac_md5.py','hmac_sha1.py','hmac_sha256.py','hmac_sha512.py']  # 添加其他不需要密钥的算法 