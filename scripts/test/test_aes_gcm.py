from Crypto.Cipher import AES
import base64

def test_decrypt():
    """测试解密功能"""
    key = "32byteslongsecretkeyforaes256!aa"
    iv = "16byteslongiv456"
    
    # 模拟 JavaScript 的 forge.util.createBuffer().toHex() 处理
    key_hex = key.encode('utf-8').hex()
    iv_hex = iv.encode('utf-8').hex()
    
    # 模拟 JavaScript 的 forge.util.hexToBytes() 处理
    key_bytes = bytes.fromhex(key_hex)
    iv_bytes = bytes.fromhex(iv_hex)
    
    print(f"密钥: {key}")
    print(f"密钥长度: {len(key_bytes)}")
    print(f"密钥十六进制: {key_hex}")
    print(f"IV: {iv}")
    print(f"IV长度: {len(iv_bytes)}")
    print(f"IV十六进制: {iv_hex}")
    
    # 创建 cipher，使用完整的 IV
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=iv_bytes)
    
    # 要解密的字符串
    encrypted_str = "IsocrZhnwPnrJ/BgMu5l0cL8nOCULEMhulbTNaskR3rpnfli"
    
    try:
        # 处理 Base64
        encrypted_str = encrypted_str.replace('-', '+').replace('_', '/')
        padding = len(encrypted_str) % 4
        if padding:
            encrypted_str += '=' * (4 - padding)
            
        decoded = base64.b64decode(encrypted_str)
        # 分离密文和认证标签（认证标签在最后16字节）
        encrypted_data = decoded[:-16]
        auth_tag = decoded[-16:]
        
        print(f"密文长度: {len(encrypted_data)}")
        print(f"密文十六进制: {encrypted_data.hex()}")
        print(f"认证标签长度: {len(auth_tag)}")
        print(f"认证标签十六进制: {auth_tag.hex()}")
        
        # 解密
        cipher.update(b'')  # 更新认证数据（这里为空）
        decrypted_data = cipher.decrypt_and_verify(encrypted_data, auth_tag)
        result = decrypted_data.decode('utf-8')
        
        print(f"解密成功！结果: {result}")
        return result
    except Exception as e:
        print(f"解密失败: {str(e)}")
        return None

if __name__ == "__main__":
    test_decrypt() 