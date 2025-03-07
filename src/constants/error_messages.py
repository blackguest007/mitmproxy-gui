class ErrorMessages:
  
    # 启动代理错误消息
    PROXY_START_ERROR = "❌ 启动代理失败: {}"

    # 秘钥错误消息
    EMPTY_KEY = "❌ 错误: 解密密钥不能为空"
    INVALID_MODE = "❌ 错误: 无效的模式"
    AES_KEY_LENGTH_ERROR = "❌ 错误: AES 密钥长度必须是 16、24 或 32 字节"
    DES_KEY_LENGTH_ERROR = "❌ 错误: DES 密钥长度必须是 8 字节,3DES 密钥长度必须是 16 或 24 字节"
    IV_LENGTH_ERROR = "❌ 错误: IV 必须是 16 字节长度"
    KEY_REQUIRED = "❌ 错误: 当前加密算法需要密钥"
    # 端口错误消息
    PORT_ERROR = "❌ 端口错误: {}"  
    
 