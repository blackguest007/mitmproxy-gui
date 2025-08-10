# Both 模式功能说明 (v1.0.5 重构版)

## 版本历史

### v1.0.4 问题描述

之前的 both 模式实现存在重大缺陷：**只处理了请求（request），没有处理响应（response）**。

### v1.0.5 完全重构

**完全重写了 bothTools 架构**，基于 BothInterceptor 统一基类，实现真正的双向加解密代理。

## 正确的 Both 模式工作流程

Both 模式应该实现完整的双向加密代理链：

### 请求阶段

1. **浏览器** → **Burp**（加密数据）
2. **Burp** → **mitmproxy**（解密数据，让 Burp 看到明文）
3. **mitmproxy** → **服务器**（明文数据）

### 响应阶段

1. **服务器** → **mitmproxy**（明文数据）
2. **mitmproxy** → **Burp**（加密数据，让 Burp 看到密文）
3. **Burp** → **浏览器**（解密数据，浏览器最终得到明文）

## v1.0.5 重构内容

### 🏗️ 统一架构设计

**引入 BothInterceptor 基类**，所有 both 工具继承此基类：

- `aes_cbc.py` - AES CBC 双向加解密 🆕
- `aes_ecb.py` - AES ECB 双向加解密 🆕
- `aes_gcm.py` - AES GCM 双向加解密 🆕
- `des_cbc.py` - DES CBC 双向加解密 🆕
- `des_ecb.py` - DES ECB 双向加解密 🆕
- `des3_cbc.py` - 3DES CBC 双向加解密 🆕
- `des3_ecb.py` - 3DES ECB 双向加解密 🆕
- `base64.py` - Base64 双向编解码 🆕
- `rsa.py` - RSA 双向加解密 🆕

### 🔧 核心实现逻辑

**统一的 process_value 接口**：

```python
def process_value(self, value: str, url: str, field: str, is_response: bool = False) -> str:
    """
    统一的值处理接口
    Args:
        is_response: False=请求(按mode处理), True=响应(按相反mode处理)
    """
    current_mode = self.mode
    if is_response:
        current_mode = 'encrypt' if self.mode == 'decrypt' else 'decrypt'

    # 根据 current_mode 执行加密或解密
    if current_mode == 'decrypt':
        return self.decrypt_logic(value)
    else:
        return self.encrypt_logic(value)
```

### 🔄 BothInterceptor 基类特性

1. **统一的请求/响应处理**
2. **自动模式切换**（is_response 参数控制）
3. **独立的日志记录**
4. **标准化的错误处理**
5. **支持 JSON 和表单格式**

## 使用示例

v1.0.5 重构后的 both 模式更加强大和稳定：

```bash
# RSA 双向模式（完整功能）
mitmdump -p 8888 -s "scripts/bothTools/rsa.py" --mode upstream:http://127.0.0.1:8080 --ssl-insecure field="password" public_key="public.pem" private_key="private.pem"

# AES-CBC 双向模式
mitmdump -p 8888 -s "scripts/bothTools/aes_cbc.py" --mode upstream:http://127.0.0.1:8080 --ssl-insecure field="data" key="your_key_16bytes" iv="your_iv_16bytes"

# Base64 双向模式
mitmdump -p 8888 -s "scripts/bothTools/base64.py" --mode upstream:http://127.0.0.1:8080 --ssl-insecure field="data"
```

## 测试验证

可以通过以下方式验证 both 模式是否正确工作：

1. 设置代理链：浏览器 → Burp(8080) → mitmproxy(8888) → 服务器
2. 在 Burp 中观察请求和响应是否都是明文
3. 在服务器端确认收到的是明文数据
4. 检查日志文件确认双向处理都在工作

## 注意事项

- 确保 Burp 和 mitmproxy 的代理链配置正确
- 检查日志文件以确认请求和响应都被正确处理
- 如果遇到问题，可以通过日志查看详细的处理过程
